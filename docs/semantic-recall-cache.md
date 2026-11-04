# Optional embedding retrieval and semantic recall

These are separate from current-rights organizational `knowledge_search`.
Skill/capability ranking uses the optional local Fastembed model and falls back
to lexical ranking on absence, invalid vectors, oversized inputs, or cache errors.
Cross-run semantic memory requires an explicitly configured vector backend;
automatic recall additionally requires `MAVERICK_AUTO_RECALL`.

## Skill and capability caches

The tenant-local `skill_embeddings.json` and `capability_embeddings.json` files
contain a versioned schema, canonical retrieval-text SHA-256, model/provider
identity, preprocessing projection, and vector dimension. Modification times
are diagnostic metadata and never authorize reuse. Skill projection remains
name, triggers, and first body line; capability projection is name plus summary.
Purpose filtering happens before ranking and outcome weights still reorder only
skills that pass the relevance threshold.

Fastembed model names do not identify immutable weights. Unless the loaded model
supplies an explicit `cache_revision`, cache reuse is limited to that loaded
instance in the current process. A process restart rebuilds safely. This trades
startup embedding work for avoiding reuse across unverified model revisions.
An unchanged warm corpus embeds only the new query. Missing vectors are batched
in groups of 64; a failed batch never publishes a partially refreshed snapshot.

Cache storage is limited to 2,048 entries, 8,192 characters per projected text,
4,096 dimensions, and 16 MiB. Non-finite, zero, mixed-dimension and incomplete
embedding batches fall back to lexical ranking. Tenant-local cross-process
locking and atomic file publication prevent partial writes. Deletions are
persisted even when all remaining entries are cache hits.

## Atomic semantic replacement and recovery

`upsert_one(document, id=..., metadata=..., embedding=...)` is the explicit
single-record replacement contract. Chroma uses native `upsert`; PostgreSQL
uses one `INSERT ... ON CONFLICT ... UPDATE`; Qdrant uses one prepared-point
`upsert(wait=True)` with deterministic tenant-scoped UUIDs. There is no prior
delete and no automatic write retry. This is not a multi-record or cross-store
transaction. A remote response can fail after the server commits; such an
outcome is unknown, rather than proof that the old bytes remain.

The current Weaviate adapter has no qualified atomic replacement contract, so
cross-run recall reports `unsupported` and uses lexical recall. Its unrelated
generic document APIs remain available. Chroma and Qdrant prepare recall vectors
locally before publishing. Qdrant uses a new `goals_v2` collection (with the
existing collision-resistant tenant prefix) to avoid mixing explicit vectors
with legacy named-vector spaces. Legacy collections are retained; historical
goals require explicit re-indexing to populate the new collection.

`semantic_recall.index_status(store=...)` reports `disabled`, `unavailable`,
`unsupported`, `absent`, `ready`, or `rebuild_required`. The lifecycle state is
tenant-local and persistent under `semantic_recall_state`. `ready` means that
this local index has no known unfinished writes; it does not certify historical
coverage of every goal in the world database or detect independent external
edits to a remote database.

Before preparing a replacement, indexing records a pending marker. A preparation
error, failed write, process crash, or ambiguous acknowledgement retains it and
causes semantic search to return `None`, which invokes the existing lexical
fallback. Successful explicit re-indexing of that same goal clears its marker;
indexing another goal cannot hide the failure. No background retry is scheduled.
Index revision checks also reject search results spanning a concurrent write.

`semantic_recall.remove_goal(goal_id, store=...)` explicitly removes only the
derived semantic record. Its persistent tombstone shares the publication lock,
so an in-flight update completes before removal and later index attempts cannot
resurrect that goal ID. A failed removal remains invisible and may be explicitly
retried. This API does not itself erase canonical world records or constitute a
full privacy-erasure workflow.

At-rest encryption remains mandatory when enabled: Chroma and PostgreSQL receive
sealed documents and precomputed vectors; Qdrant and Weaviate remain disabled in
that posture. Routing metadata contains only goal ID and status. Pilot exclusion
is rechecked after preparation, after publication, and before releasing search
results. An exclusion during publication removes the newly written record and
leaves recovery state visible. Operators should resolve exclusions and current
goal authority before explicitly retrying a failed index operation.

Native local Chroma/Qdrant tests use explicit deterministic vectors, disposable
stores, disabled telemetry, and no downloads. PostgreSQL SQL contract tests use
a fake connection; they are not live pgvector server qualification. These checks
do not establish model quality, hosted service reliability, or customer accuracy.
