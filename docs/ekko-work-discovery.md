# Ekko work discovery

Ekko finds repeated business work and builds private workflow drafts for review.
The page starts with **Find and build for me**, followed by recorded evidence,
individual task review and the opportunity workspace. Bulk building saves native
workflows; opening an individual draft remains unsaved. Neither action publishes,
schedules or executes work.

Identifying actions such as downloading a report and creating a presentation requires a reviewed `guided` integration to supply the
semantic labels `download/report` and `create/presentation`. The built-in
desktop metadata observers deliberately know only that the user moved between
allowlisted applications; it never guesses a document action from a process
name. Windows uses a fixed executable map, Mac uses a fixed application bundle
map, and local Linux X11 uses a fixed executable map. Unsupported identities are
discarded before recording. Wayland, remote X11 and headless desktops are
unavailable; supported Linux reads are bounded in a private process.

Ekko is a client-controlled sensor, so it is independent of Lightwork's
default-on governed learning. A client must complete all three gates:

1. enable Ekko through All settings or the installer;
2. enroll a named owner and device with a positive application allowlist; and
3. start a reviewed collector explicitly.

An empty allowlist means observe nothing. The sensitive communication and
system-of-record blocklist is an immutable floor and wins over
the allowlist. Pausing, stopping, revoking, or erasing is available without
provider access.

## What Ekko records

The default `application_metadata` level permits only normalized application
transitions, timestamps, and timing needed to reconstruct a sequence; its only
action is `switch` and its object type is always `none`. `guided` additionally
accepts semantic action and object labels supplied by a user or a reviewed
integration. Both modes reject raw screen pixels, window titles,
clipboard data, keystrokes, URLs, query strings, document contents, and form
values. Guided mode also rejects `email`, `message`, and system-of-record
`record` object labels even when a general-purpose browser is allowlisted; the
sensitive-data floor cannot be weakened by enrollment policy.

Raw events stay in the active tenant's local data boundary and expire after 14
days by default (hard maximum: 30 days). Opportunities are computed on demand.
Separately, an owner can explicitly save task notes and pilot observations when
private opportunity planning is enabled; this does not copy the raw events.
Provider egress is reserved and
unsupported; it must remain false, and setting it true fails
closed rather than opening a network path.

## Configure and enroll

After installation, use All settings to enable Ekko and review its limits.
On Ekko, read What Ekko records, enroll the named device and open Record activity.
The page explains the installed computer's current availability; confirm
permission, then separately choose Record allowed apps on the Lightwork computer.
Pause, Stop and withdrawal use the same current native device/session controls.
Recording happens on the computer running Lightwork, including when the browser
is on another computer. Copilot opens these same permissions without recording
anything or changing an entered choice.

An interrupted Start reply may leave a recording active. Check the current
watching state or Stop before starting again; a missing session during admission
does not prove nothing started. The temporary recording job is not a durable
Original receipt across a server restart.

The following operator configuration and compatibility commands describe the
same native policy for installations managed outside the ordinary page:

```toml
[ekko]
enable = true
planning_enabled = false # opt in separately to private opportunity plans
build_enabled = false # opt in separately to automatic workflow draft building
retention_days = 14
enrollment_days = 30
min_occurrences = 3
min_distinct_days = 2
poll_interval_seconds = 5
capture_level = "application_metadata"
allowed_apps = ["excel", "powerpoint", "chrome"]
blocked_apps = ["email", "outlook", "gmail", "chat", "teams", "slack",
                "crm", "salesforce", "erp", "sap", "database"]
provider_egress = false
```

Then use the lifecycle commands:

```text
maverick ekko enroll --device DEVICE --apps excel,powerpoint --days 30
maverick ekko status --device DEVICE
# Explicit installed-computer application-transition observer (no titles or content):
maverick ekko run --device DEVICE --observer desktop
# Or a reviewed semantic integration in guided capture mode:
maverick ekko run --device DEVICE --events reviewed-events.jsonl
maverick ekko pause --device DEVICE
maverick ekko resume --device DEVICE
maverick ekko stop --device DEVICE
maverick ekko discover --device DEVICE
maverick ekko erase --device DEVICE --yes
maverick ekko forget --device DEVICE --yes
```

`run` is foreground by design and needs an explicit observer choice.
`--observer desktop` selects the installed supported platform; `windows`,
`macos` and `linux-x11` explicitly require the named platform. The fixed maps
record only recognized, enrolled application transitions, not window titles, UI trees,
screens, clipboard, keyboard, URLs, or document content. Windows supplies the
foreground process image path transiently; Ekko immediately reduces it to the
basename for fixed-map lookup and never emits or persists the path. The
`--events` form consumes an explicitly supplied guided semantic stream. Neither
form starts at login or requests operating-system permissions on its own.

Each runner holds a single opaque collector capability in process memory. The
store retains only its one-way digest and accepts an observation only while the
matching exclusive lease and heartbeat are live. A second collector cannot
attach to the same owner/device, a crashed runner becomes `stale`, and
pause/stop/halt changes the lease authority in the same transaction as the
session state. Dashboard `running` therefore means “window authorized”; only a
`live` collector means the endpoint is actually observing approved metadata.

The ordinary CLI binds its owner scope to the current operating-system security
principal; it does not accept an owner-impersonation argument. Authenticated
dashboard deployments use the verified dashboard principal instead.

Application names in policy and guided events are canonical IDs such as
`excel`, `powerpoint`, and `chrome`, not executable names. A reviewed platform
adapter maps `EXCEL.EXE`, a macOS bundle ID, or an equivalent platform identity
to that fixed vocabulary. The bundled desktop adapters use fixed maps.
Unknown identities are dropped, never persisted verbatim. Mac/Linux native
library contracts and timeout isolation were qualified locally; physical
Mac/Linux desktop and compiled-installer acceptance remain separately unverified.

## Production collector boundary

An enterprise may run the non-detaching runner under a client-managed per-user
supervisor so it operates in the background. Review and code-sign the pinned
artifact, deploy the command with the client's endpoint-management system,
grant the narrow OS permission there, and run it as the logged-in user—not
SYSTEM or an administrator—with outbound network denied. A session-0 Windows
Service is the wrong host for foreground-window discovery because it cannot
observe the signed-in user's desktop. The current release has no
provider-analysis egress path.

Lightwork does not install a Windows service, launch agent, systemd unit, login
item, or accessibility/screen-recording permission from `maverick init`. This
keeps policy consent distinct from endpoint privilege. A production rollout
should also surface an always-visible recording indicator and bind pause/stop to
the local user session. Lightwork intentionally does not self-detach or install
autostart: the client owns that deployment decision, visible indicator, restart
policy, and content-free log collection.

Authenticated encryption detects modified policy, session, lease, and event
records. Separate consent and per-session control-authority markers prevent a
database-only replay from reviving revoked enrollment or restoring a collector
snapshot from before pause, stop, release, revoke, or erase. Like any purely
local application, Ekko cannot prove freshness against an administrator who
rolls back the complete data tree, including both the database and authority
files. Deployments whose threat model includes full-host rollback must anchor
the consent and session-control generations in an external control plane or
TPM/OS-backed monotonic authority before enabling production capture.

## Draft review boundary

Discovery requires separate occurrences across the configured number of UTC
days. Overlapping windows of the same pattern cannot inflate its occurrence
count. Repeated identical actions and periodic app loops are suppressed; a
sequence gap, reversed clock or gap longer than 30 minutes breaks a sequence.
These checks cannot establish that all work between recorded events was observed.
Shorter, more frequent patterns remain visible beside less frequent longer ones.
Evidence previews include up to 20 examples, representing distinct days first.
Discovery consumes at most 50,000 events; the page discloses when that boundary
is reached. This is a bounded sample, not a complete activity-history analysis.

App switches are labelled as app activity, never inferred document actions.
Their intervals do not establish task duration or savings. The API returns
`estimated_minutes_per_run: null` when timing is unknown; guided sequences with
positive recorded durations may show median step time, explicitly not savings.
The legacy `confidence` field remains a recurrence ranking heuristic, labelled
`confidence_kind: recurrence_heuristic`; it is not a calibrated probability and
is not shown as “% sure.” Risk signals describe observed labels, not a
completed automation assessment.

Choose **Review this opportunity** and describe the job, starting inputs,
expected output and what a person checks. Choose general work, reporting,
reconciliation or document review to tailor the draft's checks and instructions.
These owner-supplied notes are distinct from recorded evidence and travel with
the draft. They are not persisted by opening a draft; saving an opportunity plan
is a separate, explicit action.
Keep descriptions general; select actual sources and authorized connections in
the editor. The generated plan approves inputs, checks them, prepares a draft,
checks for gaps and pauses again for final review. It does not infer tool access
from an app name. Missing sources and integrations still require qualification.

Both dashboard handoffs require the reviewed evidence revision. Changed or
erased evidence is refused; retry after refreshing and reviewing the pattern.
Entered notes survive a recoverable handoff error. Device or workspace changes
clear the review and invalidate pending replies. Drafts remain unsaved and use
the normal editor's separate save, publish and execution controls.

Copilot's **Review repeated work with Ekko** operation opens the same protected
review through current access/workspace checks. It does not put recorded
activity or task notes into conversational context, select a candidate or
submit the review. This is a protected in-product handoff, not autonomous
conversational drafting. Existing `[ekko]` settings, installer setup and the
Learning operation family control these improvements; no additional capture or
provider permission is introduced. The compatibility CLI returns metadata
candidates with a next step to review them in Ekko; semantic guided proposals
retain their review-only CLI path.

## Private opportunity workspace

Enable **Save private Ekko opportunity plans** in All settings, or opt in during
the Ekko installer step (`ekko.planning_enabled`, default false). The owner must
also acknowledge private storage before each save. This capability does not
start capture, save a workflow or grant automation authority.

After reviewing an opportunity:

1. Enter runs per week, current human minutes, remaining human minutes including
   review/rework, and setup/testing hours. Blank remaining effort or setup means
   an incomplete estimate; zero must be entered explicitly. Estimated weekly
   hours equal frequency times the per-run difference divided by 60. The
   four-week estimate subtracts setup; break-even uses positive weekly savings.
   Negative estimates remain negative. These are owner assumptions, with no
   monetary ROI or verified savings claim.
2. Save the plan as **Shortlisted**, **In pilot** or **Parked for later**. The
   opportunity workspace sorts plans by estimated weekly benefit and filters
   parked work. Reopening restores the task description and assumptions.
3. Test the draft through its normal editor, connections and approval controls.
   Record the manual baseline, actual checking/rework, and whether the output
   was accepted. Accepted runs save baseline minus human effort. Rejected runs
   assume the full manual job still had to be done, making the extra effort a
   negative saving. The scorecard shows acceptance, total and median time saved,
   clearly labelled **owner-reported pilot**, separate from verified outcomes.

Plans use scoped authenticated encryption in the local Ekko database, bound to
the current tenant, owner and device. A maximum of 100 plans per device and 30
pilot runs per plan bounds storage. Saves expire within the shorter deployment
or enrollment retention period (2–30 days); explicitly saving a revision renews
that period, but recording a pilot does not. Raw events may expire earlier than
the separately saved notes. Erasing a linked evidence session, erasing the
device's data, or forgetting the device removes its linked plans. Audit events
contain identifiers/stage/count, not the entered task text or assumptions.

Current permissions are checked on every API request. Mutations also require
the fresh workspace/access/configuration context returned when reading plans,
so a stale tab cannot apply old notes to a different current context.
Concurrent edits require
the latest saved revision; an older tab cannot overwrite a newer plan. An
unconfirmed pilot can be retried with the same reference without double counting.
After an unconfirmed plan save, use **Refresh saved plans** and **Open saved plan**
to inspect the current record before retrying. Disabling planning blocks saves
and pilot additions but preserves authorized inspection and deletion. Device,
workspace or access changes clear the private view and invalidate late replies.

Copilot's **Open private opportunity plans** opens the same protected workspace
with fresh authority/context checks. It does not receive the notes, estimate
benefits conversationally, submit a plan or record a run. Direct conversational
editing remains outside this implementation. Local browser qualification uses
synthetic activity against native APIs; real desktop capture, live task execution
and independently measured savings require separate validation.

## Find and build for me

Enable **Let Ekko find and build workflow drafts** in All settings or the Ekko
installer step (`ekko.build_enabled`, default false), and enable Workflows.
The page can inspect discovery results while building is off. Select **Find
opportunities** to inspect the current sources, or acknowledge saving private
workflow drafts and select **Find and build my workflows** to discover and build
them together. Optional additional work is entered once, one task per line;
customers do not have to design each workflow themselves.

Discovery combines three sources:

- Accessible Lightwork work history: three or more distinct requests for the
  same recognized business activity. Original prompt text and result contents
  are not copied into drafts. Requests are distinct from successful execution.
- Current recorded patterns with an owner-reviewed saved task plan, or guided
  recordings that already identify semantic task steps. Guided steps can build
  directly without an additional task form. Parked plans are excluded, and
  changed or erased evidence requires renewed review.
- Tasks explicitly supplied in the optional additional-work field. These are
  customer requests, not inferred observations or proven automation benefits.

Autonomous Shoring starter-team specialist stages are excluded from the
Lightwork work-history source and Work value economic estimates. Several
internal handoffs in one team run do not establish repeated customer requests.
Their native goals, execution costs, and results remain available. Aggregating
direct or scheduled team occurrences into discovery requires a separate
team-occurrence adapter, which is not implemented.

Existing workflows with the same exact normalized business title are offered
for review. A stable source identity also preserves an earlier Ekko draft after
the customer edits its title. Existing definitions are never overwritten.
Declined, deferred and explicitly manual Work value recommendations are excluded.
App switches alone remain a context gap; they do not establish the business job.

Each new workflow is saved through the native Workflows service with input
approval, input preparation, result production, result checking and final human
review. The three agent steps pass their outputs explicitly to the next step.
Reporting, reconciliation, document work and general tasks receive different
instructions. Run ceilings are 30 minutes, $5 and one concurrent instance;
normal platform admission, provider and approval controls also apply. Building
uses deterministic templates and makes no provider calls. The agent steps call
the configured runtime only if the customer later publishes and runs the flow.

Builds proceed in batches of at most 20, with at most 250 proposals in one pass.
The page continues through eligible batches and supports **Stop after this
batch**. It reports built, existing and blocked work, preserves task descriptions
on recoverable failures, and rescans after each batch. After a lost response,
**Find opportunities** reveals drafts already saved; retrying preserves them.
An error on one task does not roll back earlier saved drafts. Current authority,
workspace context and source revisions are checked again before native writes.

Saved workflow drafts are independent artifacts with the ordinary Workflows
lifecycle. They remain until removed there; deleting or expiring an Ekko plan
does not delete an explicitly saved workflow. Review sources and connections in
the builder, test the task, then explicitly publish and run it. An automatically
built graph is not proof that integrations, credentials or business outputs are
ready. Connection readiness checks are shown, but Ekko does not crawl external
business-system contents or discover all work across a company.

Copilot's **Find and build my workflows** performs the same discovery and native
build after its sealed review and confirmation. It requires the existing
`features.copilot_operations` switch and Learning action family in addition to
the native feature permissions. Its preview discloses counts and consequences;
private saved notes are not added to conversational context. Durable, bounded
operation receipts prevent a replay from rebuilding a subsequently deleted
workflow; an interrupted operation directs the customer back to the native
discovery results. Receipts contain context, state and counts, not task text,
and are eligible for cleanup after 15 minutes, beyond the review-token lifetime.

Qualification includes native graph execution with a synthetic agent callback,
native persistence, stale-source and authority refusal, partial-build recovery,
existing-draft preservation, a lost build reply, Copilot execution/replay and
desktop/narrow browser rendering. External provider execution, autonomous
connection setup and live customer output quality remain unqualified.
