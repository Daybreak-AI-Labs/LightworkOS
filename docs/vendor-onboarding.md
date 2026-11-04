# AI vendor onboarding and evidence renewal

This bounded workflow obtains versioned Google Drive documents or uploaded evidence, builds an AI
vendor diligence assessment, records human corrections and approval, creates a
Jira Task, verifies it, and records a separate customer acceptance decision.
A renewal creates a linked case, assessment and ticket while retaining the
previous evidence and decisions. Acceptance never releases a vendor or model.

Google Drive, Jira, identity-provider and Kubernetes restore behavior are not
verified against live services.

## Run the offline demonstration

Use Python 3.11–3.12 and install the monorepo's eight packages as documented in
`CONTRIBUTING.md` / `.devcontainer/post-create.sh`. The repository root is a workspace,
not an installable Python package. Verify that `maverick.__file__` resolves to
this checkout before running tests.

```bash
python3 scripts/demo_vendor_onboarding.py \
  --state-dir /path/to/new-empty-demo-state \
  --report /path/to/demo-results.json

# Optional loopback UI; leave the process running while using the browser.
python3 scripts/demo_vendor_onboarding.py \
  --state-dir /path/to/another-new-empty-demo-state \
  --serve --port 8766
```

On Windows use the isolated environment's `python3.exe` launcher and Windows
paths. Each invocation requires a new or empty state directory. The script
refuses to overwrite existing state. Stop its local server with Ctrl+C.

Open `http://127.0.0.1:8766/third-party/vendor-onboarding`. This loopback-only
harness uses a synthetic reviewer and fake integrations. Its banner identifies
the simulation. It does not run the production application's background jobs,
call an LLM, contact a provider, or establish customer acceptance. Do not expose
this harness on a network. The production application uses normal authentication
and tenant selection.

The script exercises first onboarding, promotion and definition rollback of a
renewal classifier, a linked renewal using a new document version, and a lost
ticket-create response recovered through read-only reconciliation. The emitted
JSON includes actual domain records and measured evaluation results. To create
another synthetic request in the UI, search for `security-paper` or `native-policy`
and use Jira project key `VEND`. The initial case combines a text file, a simulated
native Google Docs export and an uploaded three-page PDF. The PDF's blank second
page checks citation numbering. Conflicting training-data statements remain
unknown until a reviewer resolves them. The renewal replaces the old upload,
changes the native document version and retains previous/current cited claims.
The report includes `document_intake` evidence for these checks. The authored
documents under `scripts/acceptance/fixtures/vendor-documents` can also be uploaded
through the UI. No actual Google export or Jira request occurs in this demo.

## Configuration and enrollment

The workflow remains disabled by default. In the app, sign in as a named
administrator, select a workspace, and open **AI vendor onboarding → Workspace
setup**. Review **Enable vendor workflow**, create the required accounts in
**Connections**, then choose the initial **Vendor review owner**, select Jira and
optional Drive, and save workspace setup. The initial owner must be a currently
active named member of this workspace with permission to manage vendor reviews; manage
that membership in **Users**. The app rechecks eligibility when saving, so a
revoked or stale selection cannot become a new owner. It does not choose the
saving administrator implicitly.
The activation turns on the existing deployment-wide prerequisite modules;
credential choices and the stable vendor review owner are saved only for the
selected workspace, with version checks and audit history. Changing the selected
credentials never silently changes the owner of earlier cases. An existing saved,
deployment-configured or historical owner is displayed as fixed; this is not an
ownership-transfer action. The saving administrator remains the credential
authority even when another member owns the vendor records. This setup does not
probe providers, share connections, grant colleagues access, or approve a workflow
action.

Connections supports either manually supplied credentials or reviewed renewable
authorization for Google Drive and Jira Cloud. Google Cloud Storage authorization
also works with the privacy discovery source picker. See
[renewable accounts](named-account-authorization.md) for app registration,
provider consent, reconnect behavior and the supported boundaries.

The installer also asks whether to enable the workflow and for its resource
owner. Deployment-managed configuration remains supported as the fallback when
no workspace binding has been saved:

```toml
[vendor_onboarding]
enable = true
resource_owner = "procurement"
document_connection = "gdrive"
ticket_connection = "jira"
reviewed_uploads = true # Local preview, Office extraction and explicit PDF transcription

[vendor_management]
enable = true
[ai_vendor_risk]
enable = true
[model_risk_assurance]
enable = true
[evidence_graph]
enable = true
[connections]
enable = true

# Optional: required for explicit deterministic renewal-flow promotion/run.
[flows]
enable = true
```

Keep the installation's existing authentication, encryption, safety and egress
policy. These settings do not enroll credentials or broaden connector grants.
Unknown onboarding keys, malformed settings and unavailable configuration are
rejected. The configured credential references must be distinct. Jira enrollment
is required for task delivery; Drive enrollment is only required for Drive search
and Drive evidence. An upload-only request does not read a Drive credential.

Use the existing Connections management surface to enroll tenant-local,
sealed records with the selected names: connector `gdrive` at the pinned HTTPS
origin `https://www.googleapis.com`, and connector `jira` at the enrolled HTTPS
origin used by the existing Jira integration. Both records must have the same
nonempty owner (credential authority), current revisions, and access grants for
the named reviewer. The Jira adapter uses a Bearer token and the existing Cloud
v3 issue operations. Validate the actual tenant's token type, endpoint, scopes,
project permissions and egress policy during live acceptance; these tests do
not establish that an arbitrary Jira token or hosting configuration works.

Open **Third parties → AI vendor onboarding** as a named authenticated user with
`operate` permission and an active tenant. Anonymous sessions and a shared static
dashboard token do not provide a named human reviewer. The request composition
derives tenant, actor, configured resource owner and enrolled credential
authority; JSON bodies cannot supply those fields or a `human` assertion.
Current authority is checked again at sensitive service boundaries. The bounded
dashboard composition binds approval and execution to the same named principal;
it is not a general delegated or multi-reviewer approval engine.

## In-app document intake

Create a request with the vendor, intended use and Jira project. Search Drive by
name and select a result for the new or currently selected request; IDs remain
an optional advanced input. A request supports up to eight sources in any mix.
For local files, choose one `.txt`, `.pdf`, `.docx` or `.xlsx` file and enter its actual
document date. Choose **Preview evidence text**, compare the text and stated limits
against your original, then explicitly confirm **Add reviewed evidence**. Repeat
for additional files. A preview changes no case record and expires after ten
minutes. File, transcription, account or request-version changes require a new
review. The document date is the uploader's assertion, separate from Drive
metadata and upload time. The installer includes this capability choice;
`vendor_onboarding.reviewed_uploads=false` disables the reviewed-upload path.
Choose **Obtain current evidence**, inspect every source's extraction status,
then **Build assessment**. A failed source blocks the whole assessment until it
is removed or replaced. File removal is available beside each selected source.

Native Google Docs use the provider's version-bracketed UTF-8 export and receive
paragraph citations. Text files also receive paragraph citations. Supported PDF
text receives citations to the rooted document pages, including blank pages in
the numbering. PDF extraction is a strict bounded subset, not a full renderer:
it has no OCR, encryption, object-stream, font-map, or XObject interpretation.
Malformed/unsupported documents and empty extraction are visibly rejected; text
that can be extracted still requires human comparison with the original.
Embedded instructions and vendor claims never grant approval or establish facts.

Word uploads extract body paragraphs and tables, with paragraph citations. Excel
uploads read visible worksheet cells and cite sheet names and cell coordinates;
unused shared strings and hidden sheets, rows and columns are excluded. Headers,
footers, images, charts, comments, styling and rendered layout are outside this
scope. Cached formula values are not recomputed; dates are not formatted. Macros,
external links, embedded active content, Word fields/tracked changes and unsafe
or oversized ZIP/XML packages are refused. The reader never launches Office or
follows document links. Drive search still supports text, Google Docs and the
existing PDF subset; download Office files and choose them locally for review.

An unreadable image-only or unsupported PDF offers an in-app transcription field.
The user supplies text, states omissions, previews it and explicitly confirms the
original comparison. This is **human transcription, not OCR**. Evidence retains
the original PDF-byte hash and a separate supplied-text hash. Quotations refer
to transcription paragraphs, never verified PDF page positions. No local OCR
engine or remote conversion service is installed or invoked by this path. A supported copy
or transcription permits the existing assessment review; it does not establish
that omitted content, business claims or legal conclusions are verified.

Limits are 1 MiB per text/Google Docs export, 8 MiB per Office upload, 16 MiB per
PDF, 32 MiB per evidence set and 120,000 characters per reviewed upload. Office
packages are bounded to 256 entries, 16 MiB expanded, 4 MiB per part, a 200:1
compression ratio, 32 sheets and 10,000 extracted paragraphs/cells. Extraction that
would omit text beyond the assessment character limit blocks assessment instead
of treating a partial scan as complete. No new parser dependency or OCR service
is installed. Raw upload bytes and complete extracted text remain transient;
retained records contain content hashes, source versions, uploader/date provenance,
parser limitations and short redacted quotations. Uploaded evidence is verified
against its retained snapshot, never described as current provider readback.

Replacing or removing evidence clears the assessment and pending action approval.
Every Drive source is checked again before task execution, including secondary
documents. Renewals retain the previous accepted case unchanged and show added,
removed and changed documents plus previous/current cited answer suggestions.
Copied uploads retain their original date; starting a renewal does not make old
evidence fresh. Conflicting claims stay unknown and require a human resolution.

## Supported operations and decisions

| Step | Supported behavior | Boundary |
|---|---|---|
| Intake | Vendor, intended use, Drive search/selection or case-scoped upload, Jira project key, 1–730 day evidence validity, optional previous case | Tenant and resource owner come from validated context |
| Evidence | Up to eight text, Google Docs, supported PDFs and reviewed local Word/Excel files; explicit PDF transcription fallback; source/date hashes and truthful page/paragraph/cell references | No OCR or full Office/PDF renderer; unsupported extraction blocks assessment; uploads and transcription have no live provider readback |
| Assessment | Existing AI vendor-risk questions, conservative source extraction, explicit unknowns, gaps and findings | Vendor assertions are not independent verification; no automatic compliance or model-quality determination |
| Review | Typed answer/note corrections, reviewer, rationale, superseded assessment/evidence references, reported review time | A model context cannot approve; unresolved gaps may remain explicitly recorded |
| External action | One exact Jira Task create, read-back and marker search using existing protocols | No update/delete/bulk action, automatic retry after ambiguity or automatic reversal |
| Outcome | Separate accepted/rejected decision, external confirmation, renewal date, elapsed time, cost status and history | Execution completed, external verified, customer accepted and released are distinct states; release stays false |
| Renewal | Linked new intake; separately collected evidence, review, approval and ticket | No autonomous ticket creation or automatic vendor authorization |
| Deterministic step | Promoted, restricted renewal-readiness classification using current case/provider state | A classification cannot approve, write a ticket, or broaden permissions |

Missing, empty, corrupted and unavailable evidence remain distinct. Collection
failure does not create an empty successful assessment. Live execution cost is
unmeasured; fake execution cost is zero. Browser review time is reported elapsed
time, not a verified measure of a person's active work. Scripted review duration
is explicitly unmeasured. Tenant-specific records and learned behavior remain
tenant-scoped; reusable evaluation material is synthetic data written for the
project. This feature does not pool data across tenants.

## Architecture and recovery contract

`vendor_onboarding_api.py` owns closed request schemas and HTTP responses.
`vendor_onboarding_composition.py` owns request authentication, current tenant,
resource owner and credential enrollment. `VendorOnboardingService` owns state
transitions and domain decisions. `ServiceContext` is an immutable validated
boundary object. Google Drive/Jira adapters own the existing provider protocols
and exact credential selection, using existing egress and SSRF protections.

The existing vendor register and AI vendor-risk assessment register remain
systems of record. Tenant-local `GovernedRecordStore` namespaces coordinate
cases, operations and improvement evidence; they do not replace those domain
registers. Existing governed-action execution and flow definition stores are
reused. The dashboard renders provider and assessment text as text, not HTML.

Each operation binds durable ID, tenant, actor, credential references, exact
payload digest, scope, evidence identity/freshness, vendor/assessment versions,
credential generations and an expiring human approval. Execution rechecks them
before and after claiming the operation. The actual Jira HTTP request resolves
and compares the approved credential generation. Verification checks the
project, type, summary, exact description, operation marker and a usable external
updated version. Receipt creation alone is insufficient.

Jira Task create has no assumed provider idempotency. The durable executing
claim precedes the call. Duplicate delivery after a claim, a timeout, uncertain
receipt persistence, or process interruption enters reconciliation. Read-only
marker search must find exactly one matching ticket and verified payload.
Missing, multiple, mismatched or unreadable results remain blocked. In particular,
zero search results do not authorize another create: indexing may lag. Reconcile
after verifying authority and provider state; an operator must resolve ambiguous
duplicates or unsupported states through the provider's normal process.

There is no universal exactly-once guarantee or automatic compensation. A Drive
file can change after the final precondition check but before Jira commits; the
providers do not share a transaction. Approval is for the recorded evidence
version and exact ticket content, not an eternal claim about current source
truth. Read-back and acceptance may also observe subsequent provider changes.

Corrections validate before domain writes. Recovery reuses a corrected
assessment only when answers, reviewer, decision and rationale match exactly.
Acceptance links the authoritative assessment recoverably and separately from
the external action. Revision conflicts require reloading and reviewing current
state. Failed storage or verification never supplies approval or acceptance.

For the runtime repairs, see [runtime accounting and recovery](runtime-accounting-recovery.md).
Restoration preserves the live Budget object and current limits; setup,
cancellation, exceptions and final output refusal converge on lifecycle
settlement. Checkpoint settlement metadata prevents ordinary replay charging.
The quota ledger atomically records cumulative usage with an idempotent receipt;
resume consults that receipt if the separate checkpoint acknowledgement was
lost. Hard loss can still lose unrecorded provider usage, and historical legacy
usage without receipts requires reconciliation. Live provider billing acceptance
remains separate. See [evidence and transport boundaries](evidence-reliability-boundaries.md)
for strict scanner failure, explicit tenant erasure and event replay semantics.

Goal signoff also retains its existing public `updated_at` float contract while
advancing the review version atomically against the stored value. Repeated or
backward wall-clock readings cannot reuse a reviewed version after result or
artifact changes. Locking on a live PostgreSQL deployment is not qualified.

## Reviewed deterministic renewal step

`EvidenceRenewalEvolution` extends `flow/evolve.py` for one typed step: classify
accepted evidence as `fresh`, `renewal_due` or `human_fallback`. The restricted
graph uses existing scope, subtraction, assignment and branch actions. It adds
no external tools or authority. Reviewed bindings name the exact `due_at` and
`now` inputs; a tool name alone cannot establish replayable parameters.

The executable example derives observations from an accepted case and current
provider state. It records typed inputs, reviewed output, rationale and source
references; proposes a candidate from at least three distinct reviewed inputs;
evaluates held-out fresh/due cases, changed inputs, invalid bindings, invalid
types and changed downstream versions; and requires explicit human promotion.
Promotion retains the exact candidate revision, evaluation and bindings digests,
flow version and generation. Later evaluation does not rewrite that approval.
Rollback creates a new definition version restoring the prior agent definition
and disables the active compiled pointer. It does not undo tickets.

The dashboard's **Check renewal readiness** invokes the approved definition
against server-derived current evidence and ticket versions. A disabled flow,
missing promotion, unsupported input, rejected/unaccepted case or changed state
retains a human/agent fallback. **Start renewal request** still requires the
normal human-reviewed workflow. Observation, proposal, evaluation, promotion and
rollback are explicit application-service operations illustrated by the runnable
script; the dashboard does not autonomously train or promote definitions.

The baseline comparison is an explicitly labeled deterministic stand-in for
agent/human renewal judgment using the same guards and reviewed bindings. It is
not an LLM benchmark or proof of an improvement learned from real agent traces.
What the script demonstrates is the path from reviewed case evidence and
explicit bindings to a restricted executable flow, evaluated and promoted with
immutable provenance and rollback. No production readiness, cost saving or
model-accuracy improvement is claimed.

## Migration, persistent deployment and restore

Existing APIs are preserved; onboarding endpoints are additive. Configuration
defaults to disabled. New workflow record namespaces and additive checkpoint JSON
settlement metadata need no destructive schema migration. Existing vendor/risk
records remain readable. Back up state before enabling the feature. Disabling
the feature retains records and effects; reverting code does not remove tickets
or erase customer decisions. Do not resume a checkpoint under an older writer
that ignores its settlement metadata without reconciling quota history.

The selected deployment path is the existing **single-replica Helm chart**.
It rejects disabled persistence even with PostgreSQL, a state mount other
than `/home/maverick/.maverick`, a conflicting `env.MAVERICK_HOME`, multiple
replicas and autoscaling. PostgreSQL centralizes the world model only; approvals,
credentials, tenant keys, checkpoints, audits and flow definitions still need the
state volume. Keep externally supplied Secrets free of state-path overrides:
Helm cannot inspect their contents. The AWS examples are not a supported
durable path for this feature.

```bash
helm lint deploy/helm/maverick
python3 scripts/check_vendor_onboarding_helm.py --helm helm \
  --output /path/to/helm-validation.json --artifacts /path/to/rendered-manifests
```

Before a real restore rehearsal:

1. Quiesce requests, workers and scheduled writes; stop the single application
   writer. Preserve outstanding operations and their current provider status.
2. Take a consistent snapshot/backup of the entire mounted state root, including
   SQLite databases and their journals, tenant encryption keys, sealed credential
   records, audits, governed records, flow definitions and checkpoints. A live
   file-by-file copy is not a consistent SQLite backup.
3. If using PostgreSQL, take a coordinated database backup and record the
   application version, configuration and snapshot pairing. Apply existing key
   custody and backup access controls; a database-only restore is insufficient.
4. Restore the matched state and database into an isolated single-writer
   installation of the same application version. Verify tenant ownership,
   decryption, named enrollment, domain records, approvals, flow versions and
   checkpoint readability before allowing writes.
5. Reconcile every executing/ambiguous external operation against the provider.
   Verify a known receipt and a interrupted-operation scenario. Do not clear
   claims or recreate tickets to make a restore look successful. Re-enable
   service only after the rehearsal's evidence and remaining exceptions are
   reviewed by the operator.

Automated evidence includes chart rendering/refusal checks and a fresh-process
test that exits after a fake provider durably writes a ticket, then restarts and
reconciles without another create. This is local storage/process recovery,
**not** proof of a Kubernetes PVC restore, disaster recovery objective or live
provider consistency.

## Focused validation

```bash
python3 -m pytest -q packages/maverick-core/tests/test_run_lifecycle_reliability.py
python3 -m pytest -q packages/maverick-core/tests/test_vendor_onboarding*.py
python3 -m pytest -q packages/maverick-core/tests/test_vendor_evidence_evolution.py
python3 -m pytest -q packages/maverick-dashboard/tests/test_vendor_onboarding_api.py
python3 -m pytest -q packages/maverick-dashboard/tests/test_event_transport_parity.py
python -m ruff check .
python -m vulture
```

On shells that do not expand test globs, pass the explicit test filenames.
Live acceptance must separately
exercise enrolled Drive/Jira permissions, identity revocation, actual version
semantics, rate limits, ambiguous provider success and persistent restore before
any production-readiness claim.
