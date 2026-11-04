# Set up privacy discovery inside Lightwork

Enable Connections, Privacy Automation, Data Discovery, and the required stock
provider adapters in Settings. These capabilities remain opt-in. A signed-in
workspace administrator can complete Lightwork's setup steps in the app; the
external provider still controls credential issuance and permission grants.

1. Open **Connections** and choose a **Privacy discovery** service preset. Save
   its exact HTTPS origin and read credential. AWS S3 has separate access key,
   secret, region, and optional session token fields. The other five stock
   readers use bearer tokens. Credential inputs are excluded from draft recovery
   and are cleared after an acknowledged save. Existing saved credentials are
   retained when an edit leaves credential fields empty.
2. Open **Find personal data** and select **Refresh connections and keys**.
   Create a named evidence key in **Evidence keys**. Lightwork generates 32
   cryptographically random bytes and seals them with the existing tenant KMS;
   the browser receives only the key's name, owner, version, and reference.
3. In **Enroll a source**, choose an enabled provider, compatible saved
   connection, and evidence key. Enter the provider's supported resource scope
   and save. The source records exact connection and key versions. Source
   selection and every subsequent settings update retain the existing revision
   and request-reference checks.
4. Select **Test saved source access** and confirm the bounded provider read.
   This tests the saved source version, not unsaved form edits. It reads at most
   one returned record/document within a 1 MiB/30-second bound, returns no source
   content, and creates no findings or report. It establishes neither complete
   coverage nor customer acceptance. Connection-level root reachability is never
   presented as this source-scope check.
5. Use the existing manual scan/schedule, leased job execution, finding review,
   independent approval, and remediation controls. The current signed-in user's
   actual connection principal is bound during in-app execution. Scheduled scan
   due processing creates jobs; the existing remediation retry scheduler does
   not independently scan providers.

## Rotation and recovery

Changing a saved connection creates a new connection revision. Every production
provider request rechecks the exact saved name, revision, connector, HTTPS
origin, and current use grant. A changed origin, revoked grant, or stale revision
cannot use an environment fallback. Select the current connection in each saved
source and explicitly save that source before further scans.

Evidence keys are private to their creating principal within the tenant. Rotate
a selected key only after reviewing the confirmation. Rotation uses a version
precondition and durable request reference: an exact retry returns its original
result and never rotates twice. Rotating removes the prior generation's active
key material. Existing source settings are not changed automatically; old key
references fail closed until the source is explicitly updated. A key rotated
during a scan prevents that scan from publishing a report under the retired
reference. Concurrent rotations have one version-precondition winner.

Reports retain a keyed comparison fingerprint and source-scope digest. Reports
from different or unverifiable key generations or source scopes cannot be
diffed as if pseudonym changes were data changes. After rotation or a scope
change, establish a fresh baseline; older reports remain readable under their
original retention policy. Missing/corrupt/cross-tenant sealed key stores are
never silently replaced. The registry bounds are 1,000 keys and 10,000 durable
key operations per tenant; capacity errors preserve existing records.

Deployment-managed environment references remain available in the source's
closed **Advanced** section for existing installations. They are a separate
explicit reference type, never a fallback for a saved connection or app key.

## Verified boundary

Automated tests exercise real local tenant-sealed storage, separate owners and
tenants, exact-reference/forged-origin denial, per-request grant checks, atomic
key rotation, source version changes during a scan, and the actual dashboard
forms using a DOM. Provider adapters and access-test responses are synthetic in
these tests. No external provider, customer, regulator, or estate-wide coverage
acceptance is claimed.
