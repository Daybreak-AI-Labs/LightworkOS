# Workspace recovery

Workspace recovery protects files inside one named workspace. A global
administrator enables **Workspace recovery** in Settings or the advanced
installer step. It is off by default. Open **Workspace recovery** from the
administrator navigation.

## Keep a recoverable copy

1. Create a recovery key and keep its download in a separate protected location.
   Import an existing key only where no recovery key is configured. The app
   never silently rotates it.
2. Review encryption-key custody. Encrypted drafts are included, but shared
   primary/rotation keys outside the workspace are not. The separate local key
   download requires explicit consent: those plaintext keys may unlock several
   workspaces. Keep them in an offline vault or secrets manager. Environment
   keys and remote key-service custody remain with their custodian.
3. Create, verify and export a snapshot outside this computer. HMAC-SHA256
   authenticates the manifest and every payload file is checked. The signing
   key is excluded. The archive itself is not encrypted and can contain
   sensitive data and tenant-local encryption keys.
4. Run **Test restore in a temporary workspace**. This really restores files,
   checks hashes and sizes, and runs SQLite integrity checks. It reports
   elapsed time and leaves the live workspace unchanged.

The latest successful temporary restore test for each snapshot is retained as
a signed report. After reloading the page, select that snapshot and view or
download its saved test result. The report records the exact archive, workspace,
operator, application build, time, restored file count and elapsed duration.
Running a new drill replaces that snapshot's previous local result; download a
copy first if your retention policy requires it. Retiring the snapshot also
removes its local drill report.

A saved result describes the archive and build tested at that time. The app
shows when the current build differs. Later workspace changes do not rewrite
the historical timestamp or prove current readiness. File and SQLite checks
do not establish decryption of every application record, a consistent business
state across files, external recovery, or permission to replace live state.

Imports are limited to 256 MiB compressed, 1 GiB expanded and 100,000 archive
members. Symlinks, junctions, hardlinks, unsafe paths, duplicate members and
inconsistent payloads are refused. At most 200 local archives are retained.
Export before retiring an archive if policy requires retention; a current or
most-recent restore's source and safety archives cannot be retired in the app.
Allow disk space for staging and rollback copies, not just compressed archives.

## Restore local workspace files

Finish active work. In the desktop menu select **Workspace recovery mode**, then
**Close local work and open recovery**. Desktop stops only its owned process
tree and starts its fixed runtime in recovery mode. It refuses to take over an
independent service listening on the local application port.

Recovery binds only to loopback and acquires a fresh single-control-plane lock
for its data root. It replaces every normal application lifespan: flow triggers,
discovery scans, consent publishing, governance loops and normal jobs do not
start. Normal application endpoints and all WebSockets are blocked. Recovery,
authentication, static assets and liveness remain available under the ordinary
administrator, authentication, tenant and same-origin controls. A request flag
cannot enable restoration in a normal dashboard.

Select and verify a snapshot, then **Prepare restore and safety snapshot**.
The app creates and verifies a copy of the current workspace. Its five-minute
review binds snapshot bytes, account, workspace, destination, application
version and exact build. Explicitly confirm to replace files and remove newer
files. Changes since the safety snapshot invalidate the review. Concurrent or
repeated requests cannot reuse it.

Automatic restore is refused if spending, in-flight holds, provider/team/MCP
budgets, signed budget receipt sidecars, tenant controls, protected external-action
history or any SQLite database
differs from the selected snapshot. The comparison catches new and removed
files as well as changed contents. It uses consistent SQLite snapshots, but
deliberately also blocks unrelated database changes: it does not guess which
fields an older accounting schema can safely accept. Reconcile these changes
with the deployment administrator before recovery; there is no quota reset,
schema bypass or automatic merging of newer ledgers. Export and temporary
restore drills remain available for that review. Refusal during preparation
creates no restore review or extra safety snapshot and leaves current state
intact; a later refusal preserves the existing review and evidence.

The external-action guard covers the proven local stores `grc_sync_outbound`,
`grc_outbound_sync_states`, `grc_outbound_sync_events`, `vendor_onboarding`
and `discovery_containment_actions`. These records prevent repeated deliveries,
ticket creation and containment operations after successful or uncertain results.
The guard does not discover every plugin or custom store's action authority.
Unknown formats or lost current authority require a reviewed recovery contract
and external reconciliation; a matching comparison is not universal restore clearance.

Before deciding how to recover, select **Compare with current workspace**.
The app verifies the entire selected archive and compares its file metadata
with current files, including consistent individual SQLite copies. The report
lists added, changed and deleted files, identifies changes covered by the
accounting, external-action and database guard, and includes every page of differences. It shows
file names, sizes and fingerprints; it does not disclose file contents.

Download the signed comparison to retain the evidence with your recovery
review. The app keeps only the latest comparison for each saved snapshot;
comparing again replaces that snapshot's previous report. Reports are bound to
the exact snapshot, workspace, signed-in administrator and application build.
A replaced report, changed snapshot or different account/build requires a new
comparison. Retiring a snapshot also removes its local comparison.

This is a captured observation. Current files can change after capture, and a
download retains the original timestamp and fingerprints. Neither unchanged
files nor a signed report establish business invariants, compatible storage
schemas, provider charges or the outcome of external actions. Comparison
never approves a restore, clears a recovery block, resets budgets or merges
old and new records. The existing isolated preparation and execution checks
remain required. Unknown or lost authority requires verified reconciliation;
safe automatic reconciliation of mixed user data and execution authority is
still outside this candidate's supported restore path.

Restore saves originals in a private authenticated transaction journal and
checks restored files before committing. Failed checks roll back the file set;
an interrupted transaction is recovered before the next restore attempt. A
receipt and safety snapshot remain available. Missing completion confirmation
is shown as unconfirmed. Remain in recovery mode if confirmation or rollback
is incomplete; review the safety snapshot and obtain administrator assistance
before restarting work. After confirmation, choose **Close recovery and return
to work** in the desktop recovery window to start a fresh normal process.

## Protect an application update and return to a prior release

The Windows desktop application has a separate whole-home installation recovery
protocol. In the isolated recovery session, a global administrator explicitly
authorizes pausing and recovering **all local workspaces and shared
administration**. The short-lived authorization is then reviewed in the desktop
**Install & updates** controls. The native shell pauses its own recovery server;
a separate retained runtime acquires the single control-plane lock before
capturing state or applying the installers.

A protected upgrade retains the exact signed old installer and runtime, verifies
the new release, and captures a verified pre-upgrade snapshot of the whole local
home. Returning to that release first captures newer work in a separate safety
snapshot, then reinstalls the old application and restores the captured local
state. Unfinished operations keep normal startup blocked and can be resumed
through the desktop maintenance controls. Completed-upgrade rollback is a
candidate local protocol with synthetic transaction and browser validation;
native MSI execution, publicly trusted signing certificates and clean-machine
acceptance remain separate Windows release gates. Signing-key or publisher
certificate rotation and remote stores or independently managed workers require
a coordinated recovery procedure and are not supported by this local path.

The same accounting, external-action and database guard applies before preparing a completed-upgrade
rollback and again before any installer executes. A preparation refusal does
not create a startup block, so the current application remains usable. If
protected state changes after installation recovery was prepared, no MSI runs and
the existing recovery block remains. That interruption requires administrator
reconciliation; this candidate does not automatically roll back a release after
protected accounting, external-action or database state changes.

At most 20 usable installation points are retained. In **Workspace recovery**,
open **Retire an unused authorization or obsolete recovery point**, select an
eligible point and explicitly confirm your retention review. This cancels the
unused authorization and permanently deletes that point's local installers,
snapshots and logs. Unfinished operations and the rollback point matching the
installed runtime cannot be retired. The server checks the exact reviewed record
again under the same operation lock before revocation or deletion.

The revoked point moves to a private retired directory before flat-file cleanup,
so an already-running download cannot recreate files at its original address.
Interrupted cleanup keeps its installation slot and can be retried from the app;
the expired authorization cannot be reused. The latest 100 compact signed
retirement receipts are kept, including who retired each point and when. Older
receipts are removed under this bounded local history policy; the receipts do
not preserve deleted snapshots or installers.

## Boundaries

### Test separately retained encryption keys

Select a saved snapshot and open **Test separately retained encryption keys**.
Choose the encryption-key ZIP previously saved in your separate custody location,
review the confirmation, and start the temporary test. The app does not download
its current keys automatically or install the uploaded keys into a live workspace.
The upload is limited to 4 MiB and admitted under the current administrator and
workspace context. It is bound to the exact inspected snapshot.

A fresh application process restores the authenticated snapshot into a private
temporary target. It verifies the custody ZIP's signature, workspace, complete
member set, key names, sizes and hashes before using its primary and rotation
keys. The child receives fresh home/config/profile/temp directories, no inherited
`MAVERICK_*` or `LIGHTWORK_*` deployment overrides or provider credentials, and
does not load archived provider configuration. Local encrypted envelopes and the
explicitly supported world-database columns are checked with the uploaded custody
copy. Missing keys do not trigger key generation. External key services are not
contacted.

The result separates verified, failed and unsupported records for each tested
format. Unmarked plaintext is not a decryption success. **Supported formats
verified** means those checks passed; custom formats, other stores and business
invariants remain outside coverage. **No encrypted records tested** is not proof
that a key copy can recover encrypted data. A wrong or incomplete copy can produce
a failed or incomplete report without altering live state.

The latest signed report for each snapshot remains available through **View last
retained-key test** and its explicit download. It binds the snapshot and custody
fingerprints, original application build, time, measurement and format counts.
Keys, decrypted contents and raw worker errors are not included. Historical
reports retain their original timestamps and identify a different current build.
Their elapsed time measures this temporary rehearsal, not production recovery
time, and snapshot age is not measured data loss. They never authorize live
restoration or clear accounting, action-history or database reconciliation.

Uploaded files and restored temporary targets are discarded after the child
finishes. A process failure, timeout or failed cleanup does not replace earlier
test evidence. Expired sessions, changed selection and interrupted requests clear
the browser's uploaded-file reference and invalidate its confirmation/download;
an administrator can explicitly retrieve an already completed report after reload.

### Other recovery requirements

- Shared administration/configuration, other tenants and keys outside the
  selected tenant are excluded. Shared key restoration requires its custodian's
  reviewed procedure; this UI never overwrites shared keys.
- PostgreSQL, remote knowledge/memory/object stores, external providers and
  independently managed workers require coordinated recovery. Configured shared
  stores and independent dispatchers block active local restore. A checkbox is
  not evidence that outside services stopped.
- Live snapshots provide consistent individual SQLite copies, not one
  transaction across all files. Checks do not certify business invariants,
  decryption of every application format, or production disaster recovery. Keep
  matching keys and test the workflows you rely on.
- Cross-version or different-build restores are refused even when version
  numbers match in the single-workspace restore path. The separate whole-home
  installation protocol above restores the exact retained application before
  its captured state; it never asks an older reader to consume newer accounting
  or storage records.
- Native switching and MSI installation need Windows native acceptance.
  Python/API and DOM tests do not verify a clean Windows machine.

## Tenant identity history

Tenant identity history is never rolled back with ordinary workspace files.
Whole-installation snapshots include immutable namespace claims under
`.tenant-namespaces/<shard>/<digest>.json` and deletion tombstones under
`.tenant-deletions/<digest>.json`. A workspace purge retains both roots. A signed
older snapshot cannot erase or rewrite an existing claim or retirement, even
through a direct restore with `force=True`; recovery comparison reports these as
protected authority. An additive restore retains a newer deletion, so an older
active roster entry cannot reactivate that tenant.

New history from a restore is published atomically without replacement. If
publication fails, ordinary files roll back while any already-published identity
history stays reserved. Recovery of an older transaction journal follows the same
rule. This intentionally favors an unused reserved name over reviving an old
tenant's roles or data. An isolated bootstrap keeps the exact historical bytes
under a startup hold until current authority is reconciled; authenticated backup
provenance alone is not permission to resume that tenant.

## Verification drills

Two scripts in a source checkout exercise recovery against synthetic data:

- `python scripts/acceptance/workspace_recovery_drill.py` creates an isolated
  temporary home with an encrypted synthetic draft and SQLite fixture, performs
  a real restore, checks the draft with its retained fixture key, prints
  measurements and removes its state.
- `python scripts/acceptance/workspace_application_recovery.py --output application-recovery.json`
  restores an authenticated snapshot into a fresh target process and reads it
  back through `DraftStore` and `WorldModel`. Writes acknowledged before the
  snapshot must be recovered, later writes must be absent, and missing custody
  or a wrong primary key must fail before application reads. The JSON output
  records the application and archive identities, the checks and the observed
  timings.

Neither drill restores a real workspace, starts a server or contacts providers.
Their timings are bounds for the synthetic fixture, not production RTO/RPO, and
they do not establish external-store or native installer recovery.
