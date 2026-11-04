# Persistence authority and recovery inventory

The control plane requires one active owner. Selecting PostgreSQL for the
world model or governed records does not make every queue, file, key, approval,
audit chain and instruction store shared. This inventory does not enable high
availability or relax deployment guards.

The machine-readable [inventory](persistence-authorities.json) classifies each
Python source file found by the persistence-seam scan or classified by owner
review, including the shared A2A store, PostgreSQL primitives, learning-key schema helper
and signed client-erasure receipts. The learning-key helper changes the keys of
the four existing learning tables in the owning transaction; it creates no
separate business namespace. The inventory includes
explicit test/tooling exclusions. Each entry records its purpose, semantic
contract, owning module or delegated owner, exact source sites, literal path
hints, observed transaction/schema markers and governed namespace restore policy.
The contract family supplies its transaction, migration, recovery and ownership
limits. Mechanism markers are source observations, not proof that every write
uses them. A `data_dir`, `connect`, or `write_text` call alone proves no durable
authority.

The inventory is a source and contract classification: every listed persistence
seam and module purpose is classified, and the owning implementations and the
recovery registry define the contracts. It is not a test of every branch or a
native deployment qualification. Line references describe the source when the
inventory was last updated and move with edits.

## Store owners and boundaries

| Family | Canonical owner and transaction | Migration and recovery requirement |
|---|---|---|
| World goals, approvals, messages, facts, attachment admissions | `world_model.py` / `world_model_backends/postgres.py`; SQLite or tenant-bound PG transactions | Schema ladder and consistent backup; preserve attempt receipts, invalidate or reconcile restored approvals/active work. Local pre-migration snapshots are best-effort and are not a rollback guarantee. |
| Governed domain records | `governed_records.py` / `privacy_ops._RecordStore`; domain namespace, monotonic revision, CAS, record-bound audit outbox; optional encrypted PG rows with RLS | Domain schema and exact tenant binding remain authoritative. Migrate rows, revisions and outbox together; local blobs and application-level locks remain separate. |
| Shared A2A task claims | `a2a_store.py` / `governed_record_batch.py`; namespace transaction joins claim, task lookup, retained-byte accounting and terminal index; encrypted `a2a/tasks.authority.sealed` binds the local root to the shared authority generation and prevents local downgrade | Explicit [offline migration](a2a-claim-authority.md) in `a2a_migration.py` holds source/owner locks, validates both source digests and quotas, imports 20-row checkpoints, preserves consumed and unknown identities, and retains a verified private archive before source removal. Existing local ledgers are refused during ordinary shared admission. Restored binding receipts block startup pending current authority reconciliation. This does not certify the whole cluster. |
| SQLite governance families | Core privacy, consent, evidence, vendor, trust-center and governance-agent stores; dashboard inline credential/custody stores | Each owner has its own schema/integrity/revision contract. Stop/fence its writer, snapshot consistently, preserve pending operations and key custody. Unknown SQLite blocks bootstrap; it is not automatically replayed. |
| Flow definitions, runs and payloads | `flow/store.py` and `flow/payloads.py`; canonical JSON plus immutable tenant/run-bound encrypted payloads | Preserve approved release/input binding and full checkpoint payload. `flow/run_index.py` is a rebuildable projection, not permission to resume a run. |
| Channels and other effect queues | Channel journal, polling cursor, `job_queue`, federation, form events, scheduler configs | Keep input identity, execution claim, saved output, per-send receipt and unknown outcome distinct. Restored channel namespaces are explicitly blocked until supported no-replay reconciliation exists. |
| Accounting and stop authority | Provider spend, quotas, budget receipts, tenant reservations, shared/local HALT | Preserve spend history, exact stop generation and attempt identity. A partition or lost accounting authority cannot grant new budget or clear a newer stop. |
| Identity, keys and configuration | Tenant registry/KMS, at-rest keys, connection/OAuth vaults, RBAC, SCIM, invites, replay and revocation files, runtime settings | Authenticate custody and tenant/purpose binding. Restore exact key generations only through the recovery protocol; unsupported identity/config authority stays blocked. |
| Audit and evidence | Signed bodies, chains, checkpoints, anchors, evidence receipt ledgers and custody state | Transfer signatures, keys, anchors, retention and source coverage together. Indexes can accelerate reads but cannot recreate evidence or erase a reported gap. |
| Client-erasure receipts | `client_erasure.py`; signed intent, prepared inventory and terminal outcome are retained under the installation home outside the erased tenant root | Preserve the signed chain and public verification key as offboarding evidence. An intent or prepared event is not proof of completion; these receipts cannot restore erased tenant data, and tenant workspace backup does not capture them. |
| Learning and research | Promotion ledger, evaluator accounting, generated instructions, skill/code artifacts, archives and model pointers | Preserve source/model/evaluator version, confirmation accounting and approval. PostgreSQL's existing four learning tables use the checked [tenant-key migration](learning-store-tenant-keys.md), shared by WorldModel v39 and standalone initialization; table/row and NULL-partition identity are retained, with one caller-owned transaction and refusal on unrecognized constraints. Some logs are explicitly discarded on bootstrap; instruction, routing and promotion state remains protected. Research opt-in does not make authority disposable. |
| Source documents and business records | Attachment blobs, knowledge corpus, book of work, assessments and user task data | Preserve source hashes, provenance and record relationships. Migrate canonical source before rebuilding embeddings or projections. Not all persistent data authorizes execution. |
| Derived state | Exact-key lookup, flow metadata index, recall markers, model discovery and content-bound caches | Rebuild from current canonical sources; preserve removal/incomplete state until reconciled. A derived label never overrides a stricter registry policy. |
| Preferences and drafts | Principal-bound read/snooze/pin preferences, saved views, draft and support previews | Restore as private data only. A restored draft or snooze cannot approve a live workflow or grant access. |
| External and temporary work | User files, connected external databases, socket clients, in-memory analytics, private document jobs | External owners control durability. Local backup does not establish provider effects; temporary job completion requires final publication through its owner. |
| Installation | Release artifacts and installation recovery receipts | Installer acceptance fixtures are test state. Signed release outputs and reviewed installation transactions retain their own admission protocol. |

## Recovery is a closed disposition, not a filename guess

[`recovery_authorities.py`](../../packages/maverick-core/maverick/recovery_authorities.py)
is the runtime source of truth. The inventory reuses its exact namespace policies.
The registry contract scans core and channel store declarations, including literal
module constants. The inventory contract additionally covers dashboard governed
stores. The sole documented ordinary-data exception is `action_center_preferences`:
it stores read/snooze preferences, not source-work authorization.

Unknown SQLite receives a blocking policy. Named JSON authorities use their
specific policy: authenticated preservation for supported records/credentials,
safe retirement or transformation for supported work, explicit discard for
specified derived inputs, or a global startup block. A blocker is not cleared by
generic administrator confirmation when no supported reconciliation exists.

Public-form `form-recovery` journals and their signed `.accepted` markers are
execution authority: an older restored absence could run a submission the owner
decided to stop. A restored copy containing either file is retained as a
global-start blocker pending current authority reconciliation. At delivery,
missing or inconsistent journal/marker pairs refuse the submission; a crash
between initial marker creation and the first journal append can leave a safe
hold with no automatic repair path. A snapshot from before both files existed
has no absence proof and can still replay the submission.

Caller-configured state paths cannot be assigned a safe bootstrap policy from
their extension. They require the owning module's schema, signer and idempotency
contract and an explicit target/path binding. The same rule applies to research
archives and user workspace state.
The inventory lists these owners; it does not claim an automatic migration for
every custom path.

## Required qualification before relaxing the singleton

Choose a transaction owner for each remaining local authority and preserve its
schema, tenant scope, key custody, revision and external-effect identity. Shared
mutations must check the owning fence in the same transaction as their target
write. Local file locks or a Redis pre-check do not substitute for that condition.
Source blobs, signing custody and append chains need an explicit shared or
single-owned service boundary as well as a shared database.

Before enabling two control planes, qualify competing claims/approvals, process
death at each commit/publication boundary, lost database/key authority, network
partition and stale-owner mutations. Recover each to an explicit operator state
without replaying an uncertain effect. Evidence for one shared store must not be
promoted into system-wide high-availability acceptance.

Local tests: `python -m pytest -q packages/maverick-core/tests/test_persistence_authority_inventory.py packages/maverick-core/tests/test_recovery_authority_registry.py`.
These check the closed namespace inventory, ownership/disposition fields and
specific authority-versus-cache/export counterexamples. They are drift checks,
not substitutes for crash/partition/native-store qualification.
