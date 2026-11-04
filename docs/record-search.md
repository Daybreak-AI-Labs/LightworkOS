# Business record search

The Ctrl+K / Cmd+K finder includes current business records as well as allowed
navigation pages. Search by name, reference, state, or displayed version; filter
by vendors, evidence, assessments, decisions, tasks, or reports. Selecting a
result opens the exact record in its ordinary review screen. Search never runs,
approves, downloads, or publishes a record.

`features.record_search` defaults to true and has a Settings switch and installer
prompt. Disabling it retains the local page finder. Browser requests carry an
opaque account/workspace binding. Results are never persisted in browser storage
or a shared search database. POST requests keep search text out of query URLs.

Each search reads the current authorized source projection. Task ownership,
department grants, vendor workflow resource ownership, vault metadata access,
and executive report role views are applied before matching or result counts.
Only explicitly selected metadata fields enter the temporary index. Document
contents, extracted evidence, task descriptions/results, answers, review notes,
provider credentials, storage locators, and download tokens are excluded.

Current sources are the vendor register, vendor onboarding requests and their
persisted evidence/latest human decision, saved questionnaires and current final
decisions, tasks and completed deliverables, governed document vault metadata,
and executive reports. This is not a claim to index every internal store or the
entire decision history. It does not invoke Drive, Jira, model, or other provider
APIs. Existing source integrity and configuration checks remain authoritative.

Search coverage reports current, partial, or unavailable for each selected
source. At most 1,000 authorized metadata entries per source enter one search;
source adapters additionally cap task/questionnaire reads at 1,000 heads and
vault/report lists at 500. Vendor stores retain their existing bounded capacity
checks. A partial index may omit records beyond these limits. Inaccessible or
failed sources expose no record count or underlying error text. Matching totals
describe the searched index, not an exhaustive workspace census. The response
includes its check time; there is no delayed background indexing to wait for.

Paging sends the previous metadata snapshot digest. If records or permissions
change between pages, the server rejects that page and the UI asks for a fresh
search rather than silently skipping/repeating results. A workspace switch or
newer query invalidates pending browser results. All matching source fields and
links are rendered as text with an allowlist of in-app review destinations.

Automated checks use isolated local stores and synthetic records. Node DOM
tests cover keyboard behavior, asynchronous interruption, stale paging, and
workspace binding; they do not substitute for browser rendering or acceptance
testing.

## Historical metadata

Choose **Historical metadata** in the finder, then a source and optional UTC
calendar dates. Blank queries browse the chosen source; named queries match
metadata only. **Oldest first** reaches older work directly. Continue with
**Search next history window**, including when a window has no matches.
Counts describe returned matches, never an exhaustive source census. A final
window means the selected source/date sequence is exhausted only if none of its
preceding windows was skipped. Changed filters or permissions require a fresh
sequence. Source workspaces remain available from coverage recovery links.

History covers tasks, projects, workflows/templates, durable automations,
exact-owner connections, shared fact names, questionnaires, document-vault
heads, executive reports, vendors/onboarding evidence and current project
reviews. Auth-off uses the unowned scope, never every employee. Template
visibility uses exact ownership or the canonical verified publication policy.
Questionnaire departments and report role views are applied before matching
and counts. Internal file scan positions stay inside tenant/context-bound
sealed cursors; an empty window is never an inaccessible-record count. Fact values and private user/task namespaces never enter discovery.
Source dates are labelled: most are creation dates; workflows/questionnaires
use last saved time, automations/facts last changed time. Unknown-date records
are omitted only when a date filter is selected.

Tasks, projects and facts use tenant/owner-filtered native SQL windows.
Migration 45 adds owner/date indexes for both SQLite and PostgreSQL, plus a
shared-fact date index. Vault and report adapters keep native integrity/role
checks; questionnaire windows authorize each head by current type before projection. Each
native window returns at most 250 records, each response at most 50 matches.
Snapshot proofs stream only metadata, with a 50,000-head and cooperative
three-second scan budget checked between batches/records. A larger source asks
for narrower dates and reports partial coverage; it is never reported empty
and complete. Other governed catalogs retain their native bounded inventory
limits. No asynchronous index, provider request, model call or full-text copy
is created. Existing feature configuration, Settings and installer controls
for record discovery govern both metadata modes.

Copilot's **Find historical record metadata** uses this same service and
returns the continuation cursor internally. Ask for the next window or narrow
the dates. Its native-screen link opens the finder in history mode. Returned
cursors are sealed and bind exact filters/current context and are positions, never grants;
opening a result performs its ordinary current authorization again.

Migration 45 adds owner/date indexes and preserves encrypted values. Rollback means stop
using historical discovery and roll forward to a compatible build, or use the
ordinary reviewed pre-upgrade backup restore. Do not lower the schema version
or rewrite released migrations; older binaries reject newer schemas.

Each search window returns at most 250 rows and stops at its scan limit, so
large histories are reached page by page through the continuation cursor. Owner, department and role exclusions and private-body
exclusion apply to every window.
PostgreSQL service execution and installed browser performance remain separate
qualification work; these figures describe synthetic local SQLite fixtures.
