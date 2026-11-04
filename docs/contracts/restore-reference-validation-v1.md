# Staged local restore reference validation v1

- Validator: `lightwork.restore-reference-validation.v1`
- Applies to: local restores

## Behavior

A correctly signed archive with matching payload hashes can still contain a
vendor-onboarding case whose vendor, assessment, or renewal parent is absent.
The restore path checks supported application references in its private
staging directory before recovering an earlier transaction or publishing any
application file, so such an archive cannot produce a successful recovery
receipt. `force=True` does not bypass this check.

The recovery center performs the same preflight before creating a review/safety
snapshot and again before consuming a reviewed live restore. A failed drill
does not issue a successful drill report. Hash-only inspection remains useful
and remains explicitly distinct from application-reference validation.

## Supported scope

The versioned validator is `lightwork.restore-reference-validation.v1`:

- Local JSON records in `vendor_onboarding`, `vendor_management`, and
  `ai_vendor_risk`, with their existing v1 schemas and store/file identities.
- A case's `vendor_id` must exist in its workspace and match its owner and
  `vendor_name` (using the vendor register's trimmed lowercase identity).
- A non-null case `assessment.id` must exist in that workspace and carry the
  matching tenant digest and `vendor` name (using the assessment authority's
  whitespace-normalized casefold identity).
- A non-null `renewal_of` must resolve to another case with the same tenant,
  owner, and vendor reference.
- Whole-installation recovery resolves each `tenants/<encoded-tenant>` subtree
  independently. Another tenant's matching record ID cannot satisfy a reference.

The validator reads at most 16 MiB per record, 64 MiB across supported records,
and 25,000 records. Exceeding these bounds requires a reviewed recovery plan.
Duplicate-key, malformed, non-finite, unknown-schema and mismatched-identity
JSON is rejected with an affected file and field/reference diagnostic. Record
payload values are not copied into diagnostics.

## Compatibility boundaries

Full replacement is required whenever an additive restore would involve any
supported governed-store directory in the archive or existing live tree. An
overlay could otherwise leave retained live records pointing at replaced
targets. This version fails closed instead of claiming to validate that merged
state. Existing isolated in-app and installation restores use full replacement.

Encrypted envelopes in supported stores are rejected before publication with a
key-custody/decryption diagnostic. The validator never imports keys from a
snapshot or tries ambient decryption, which could select the wrong tenant key
or mutate shared key state. A custody test for other encrypted formats is not a
waiver of this boundary.

Restore is therefore unavailable for profiles that persist sealed payloads in
these covered stores; a refusal is not proof of successful encrypted recovery.
Other encrypted drafts and database columns remain outside this check. The
local governed-record backend writes plain JSON; shared encrypted Postgres
records are excluded from local workspace recovery.

These checks do not validate every field in a domain schema, audit outbox or
signature authority, historical assessment versions, complete renewal lineage,
general evidence-graph links, all cross-record application invariants, decryption
of unrelated stores, or provider state. Retained evidence is not reclassified
as fresh. Local restoration does not reverse any external effect. Recovery
reports retain these scope limits and do not claim complete business acceptance.

The application must still be quiescent under the existing isolated recovery
procedure. The low-level restore lock serializes restores; it does not stop
every ordinary application writer. This validator adds no concurrency guarantee.

## Schema version admission

The runtime's native SQLite world schema version is `world_model.SCHEMA_VERSION`.
Startup examines an existing
nonempty database through a read-only connection before a writable connection,
WAL-mode change, schema bootstrap, or migration. This read includes committed
WAL state. The existing per-world admission lock may create or update its lock
sidecar; the guarantee concerns the database, WAL, and rollback journal. A
future schema or invalid metadata produces an actionable error directing the
operator to a compatible release or backup. It is not repaired in place.

Both startup and staged restore preserve the legacy policy: an absent or empty
`schema_version` table is unversioned legacy state. A nonempty version table
must be a real table containing exactly one positive native SQLite integer.
Views, duplicate rows, wrong columns, nulls, text, real numbers and nonpositive
versions are incompatible. The metadata check admits versions 1 through
`SCHEMA_VERSION`;
this is not a claim that every arbitrary table layout with such a marker is
valid. The existing migration ladder and staged reference checks still apply.

| Boundary | Supported behavior | Action on incompatibility |
| --- | --- | --- |
| Current runtime opening a prior native world | Existing forward migrations | Block future/invalid metadata before writable open |
| Low-level signed v2 archive restore | Root manifest version equals staged root database; discovered native world schemas are checked under any filename or tenant path | Block unsupported/malformed/mismatched versions before transaction recovery or publication, including with `force=True` |
| Legacy unsigned v1 archive | Existing explicit administrator opt-in; version declaration may be absent, but actual native database checks still apply | Integrity checks provide no authentication; unsupported state still blocks |
| In-app snapshot drill, review, and apply | Recovery binding schema 1 with the same application version, exact build identity, and tenant | Different versions/builds require the matching build or a reviewed compatibility migration |
| Restoring a pre-upgrade snapshot | Recover the prior bytes and reopen under the current forward migration ladder | No automatic down-migration or arbitrary older-binary rollback is promised |

Snapshot creation reads native version metadata from the SQLite online-backup
copy, avoiding a race between a live version read and the copied payload.
Private copied databases are read with SQLite `immutable=1` because the online
backup has already folded in committed WAL pages. SQLite discovery uses the
same conventional extensions and file-header recognition as snapshot creation,
including custom names and whole-home tenant paths. The native `schema_version`
table is the world metadata marker (only `WorldModel` creates that table). Other SQLite stores without it remain unclassified;
their component version columns and `PRAGMA user_version` are not interpreted
as world schema versions. The guard does not certify unrelated component schemas.
Restored SQLite files with paired `-wal`, `-shm`, or `-journal` sidecars are
refused with a fresh checkpointed snapshot/reviewed migration action, so a
sidecar cannot hide either the native marker or a newer version. Orphan
conventional `world.db` sidecars also remain refused. Hash-only archive inspection
remains an integrity/authentication check, not a compatibility approval.

## Conformance tests

`test_backup_schema_compatibility.py` builds a prior-schema database with the
migration ladder, restores a signed snapshot of it into a fresh root and reopens
it under the current schema with record identity, title and owner preserved. It
also covers future and malformed database and manifest metadata, custom root and
tenant filenames, and incompatible drill, review and apply attempts, which must
leave database bytes and restore authority unchanged.
`test_world_model_compatibility.py` covers startup admission, including a future
version committed only in WAL. These fixtures are derived from the source
migration ladder; they do not exercise historical installers, installed
upgrade or uninstall, external stores, encrypted backend migrations or
provider-side rollback.

`test_restore_application_validation.py` builds signed, hash-verified archives
and checks that rejection happens before `_recover_transactions` or
`_apply_transaction` can run. It covers dangling references, binding failures,
valid replacement, additive refusal, sealed-format refusal and cross-tenant
whole-home recovery, and restores an accepted case and its renewal into a fresh
home and reopens both through a fresh `VendorOnboardingService` without
repeating the ticket create. `test_workspace_recovery.py` covers the in-app
drill and review boundaries.
