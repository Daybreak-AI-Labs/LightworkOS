# The knowledge plane

Per-domain document recall (RAG) for the workforce: a specialist agent grounds
its answers in the documents its department is allowed to see, via the
`knowledge_search` tool. Knowledge is an **opt-in extra** — the kernel never
requires `maverick-knowledge`, and RAG is off until you enable it.

```toml
[knowledge]
enable   = true
embedder = "local"     # hosted | local | deterministic
store    = "sqlite"    # sqlite | pgvector | qdrant
```

## Storage: pick a backend per deployment

The adapters support three backends, with different publication guarantees.
SQLite and pgvector support atomic governed document ingestion. Qdrant supports
existing-corpus reads and erasure; new governed publication is refused because
the adapter lacks a shared atomic provenance and embedding-identity fence.
Qualify the selected backend with your corpus.

| Backend    | When                                            | Notes |
|------------|-------------------------------------------------|-------|
| **sqlite** (default) | Single box, SMB, air-gapped | Brute-force cosine over local records; measure latency at the intended corpus size. |
| **pgvector** | Deployments already operating Postgres | Needs `maverick-knowledge[pgvector]`, the `vector` extension, and verified database isolation, backup and permissions. |
| **qdrant** | Existing retrieval infrastructure | Needs `maverick-knowledge[qdrant]`. Existing exact documents remain readable and erasable. New ingestion, interrupted-document repair and in-place reindex are refused; migrate ingestion to SQLite or pgvector. |

The default knowledge store can be self-hosted. Whether document content leaves
your deployment also depends on the embedder, model provider, and connectors
you enable. Review those settings and outbound policy before adding sensitive
documents.

### pgvector

```toml
[knowledge]
enable = true
store  = "pgvector"
dsn    = "postgresql://db-host/lightwork"   # credentials via MAVERICK_KNOWLEDGE_DSN / MAVERICK_PG_DSN env
dim    = 1024                               # must match your embedder's width
```

Per-workspace isolation is preserved: rows are namespaced by a hash of the
workspace, so one shared cluster still keeps tenants apart.

### qdrant

```toml
[knowledge]
enable  = true
store   = "qdrant"
url     = "http://qdrant:6333"     # or QDRANT_URL
dim     = 1024
# Qdrant key: set store_api_key in All settings, or QDRANT_API_KEY on the server.
# The separate api_key setting is only for the embedding service.
```

This adapter's low-level upsert does not provide atomic document admission.
New governed ingestion fails with an actionable error before document embedding
or vector/document writes. Read attempts may still produce local accounting
receipts. A complete existing document with the same text and provenance can
still satisfy an idempotent, read-only retry. No backend is silently substituted.
Qdrant's newer conditional point writes do not by themselves supply this
adapter's required multi-chunk document and collection-identity transaction;
distributed publication on Qdrant is not qualified.
Chroma is a separate core recall adapter, not a `KnowledgeBase` storage backend.

## Embedders

`hosted` (Voyage; its key is `[knowledge] api_key`, then
`MAVERICK_EMBED_API_KEY`, then `VOYAGE_API_KEY` on Voyage's own endpoint), `local` (on-box
sentence-transformers, no key), or `deterministic` (a hashing stub — offline and
keyless, but low recall quality; for tests and smoke runs only). **Meaningful
semantic recall needs `local` or `hosted`.** Changing an embedder or model can
change the vector space even when its dimension stays the same. Chunks record
an embedding identity; retrieval and ingestion refuse a mixed or incompatible
collection instead of silently comparing unrelated vectors.

Existing untagged collections require an explicit migration. With the intended
embedding configuration active, run
`maverick knowledge reindex <collection> --tenant <tenant>` for a supported
SQLite or pgvector store. Reindex uses the existing complete chunk text and
preserves chunk IDs, provenance and content commitments. Vector replacement is
atomic against the captured collection state; a concurrent corpus change
requires a retry. This in-place operation is bounded to 100,000 chunks. A
pgvector store also requires the replacement vectors to match the existing
table dimension; changing dimensions requires a new store and an explicit
corpus migration. For Qdrant, migrate the source corpus into a SQLite or pgvector
store and switch the configured knowledge sources after verifying it; Qdrant
in-place reindex and new governed ingestion are refused before embedding work.

Hosted identities bind the configured provider, model, endpoint, dimensions
and optional `[knowledge] revision`. That revision is an operator-supplied
identity, not independent proof of which remote weights served a request.
Changing provider weights without changing a published or configured revision
cannot be inferred from equal-sized vectors. Opaque custom embedder instances
do not share a persistent cache identity.

## Governance

Every chunk is provenance-stamped at ingest: `source` (the citation), `subject`
(the data-subject key, when the document belongs to one), `trust_tier`
(3 first-party … 0 external), `sensitivity`, `ingested_by`, `ingested_at`, and a
`doc_sha256` content hash. Ingestion is screened for prompt-injection on the way
in and recorded on the signed audit chain (`evidence_capture`).

Within one collection, a document digest binds its content, chunk layout and
provenance at publication. SQLite and pgvector compare that binding inside the
same transaction as insertion, including when independent workers have both
read an absent document. Conflicting provenance is rejected without partial
publication. Matching retries retain the first admitted rows and timestamp;
repair of missing matching chunks uses that same timestamp. Embedding-identity
checks remain inside the transaction and continue to fence reindex operations.

One document may contain at most 2,048 chunks. Ingestion checks the complete
chunk count before embedding or publication and rejects larger documents;
split them into separately attributable sources. The bound also applies to
exact-document verification, so an oversized document cannot be published and
then reported as a failed ingestion solely because verification is truncated.

Because chunks carry a subject, the knowledge plane participates in the platform's
compliance flows:

- **Right to erasure (GDPR Art. 17).** `maverick erase --channel X --user Y`
  removes the subject's document chunks along with their world-model rows, and
  the erase's signed audit event records the count.
- **Erasure verification.** `maverick erase-verify` folds the subject's residual
  knowledge-chunk count into its verdict. A subject is not "clean" while any of
  their documents survive in the vector store, and an unavailable configured
  knowledge store yields `INDETERMINATE` rather than an assumed zero.
- **Knowledge-only cleanup.** `maverick knowledge residual --channel X --user Y`
  and `maverick knowledge erase-subject ...` for targeted checks and removals.

Retrieval respects the compartment bulkheads: a pack's `knowledge_search` is
bound to its own `knowledge_sources`, so a finance specialist never retrieves
another department's documents.

## Saved company folders and spaces

Saved SharePoint, OneDrive, Google Drive and Confluence sources read the selected
folder's direct files or the selected space's current pages; subfolders need
separate sources. Each refresh is bounded by the `[knowledge_sources]` table
(also under Settings > All settings, Memory & learning):

```toml
[knowledge_sources]
max_items           = 64   # 1-1000: direct items one refresh may list
max_pages           = 16   # 1-200: provider listing pages (each holds up to 64 items)
max_download_mib    = 4    # 1-32: largest SharePoint, OneDrive or Drive file downloaded
max_text_kib        = 256  # 1-8192: extracted text kept per refresh
max_refresh_minutes = 5    # 1-60: wall-clock minutes one refresh may run
permission_filter   = "off" # "off" (default) or "by_email": see below
```

### Matching each file's sharing permissions

By default, anyone the saved account is shared with can use the cached content of
the source. Set `permission_filter = "by_email"` to show each file only to the
people it is shared with. With this setting, every refresh reads each item's
sharing permission from the provider and keeps only this record per item: the
lower-case email addresses it is shared with, the email domains it is shared with,
whether it is shared by link ("anyone"), and whether any group is granted access.
Tokens and raw provider responses are never stored.

At use, a file is shown only to a signed-in person who has a verified email, when
that email matches one of the recorded addresses, when its domain matches a recorded
domain, or when the file is shared by link. The verified address comes only from an
OIDC sign-in whose `email` claim the provider marks `email_verified: true`. Many
identity providers do not send that flag, and then no address is matched. Usernames,
UPNs and subject identifiers are never used as the address. SAML sign-ins carry no
such address, because a SAML assertion does not prove that an email is verified, so
SAML users see no files under this setting. API keys, agents and workers have no
address either, so they see no files under this setting.

Files are withheld, and not named, when:

- they are shared only with a group. Group grants are **not expanded**, so group
  members are not read and such files are withheld, even for members of the group;
- the provider's permissions could not be read, or their shape was not understood;
- the saved source has not been refreshed while this setting is on. A refresh made
  with the setting off removes the sharing records it reuses, so turning the setting
  back on withholds those files until the next refresh. Refresh the source once after
  changing the setting;
- the signed-in person has no verified address.

A refresh that does not complete keeps the previous snapshot, and its sharing
records, until that snapshot's freshness window ends. Only a completed refresh reads sharing
again.

Search reports how many files were withheld for permissions. A refresh whose
permission reads fail still completes; the affected files stay withheld until a
later refresh reads them.

Provider notes (not all verified against live tenants): Microsoft Graph's
`driveItem` permissions and their `invitation.email` and `grantedToIdentitiesV2`
fields are documented; whether Graph returns an email for each user grant depends on
the tenant, so grants without one are withheld. Google Drive's `permissions.list`
endpoint and `pageToken` paging are documented; the `emailAddress`, `domain` and
`type` field names are not verified here. Confluence page read restrictions are
read per page; a page with no restriction of its own inherits space permissions,
which are not read, so it is withheld. Confluence user restrictions without an
address are withheld as well.

`max_download_mib` applies to SharePoint, OneDrive and Google Drive files. A
Confluence page is read as JSON under a fixed 2 MiB limit that this setting does
not change, and a larger page is refused with a message that says so.

The defaults are the historical bounds. A value outside its range stops the
saved-source list, saving and refreshes with a message that names the setting;
a save is refused before anything is written. Each refresh reads the current
values. A retained snapshot still validates after
`max_items` is lowered. Its text is checked against the current `max_text_kib`
whenever it is used, and the exact copy used by specialists is held to that same
setting. Listings read `max_pages` pages of 64 items, so raise `max_pages` along
with `max_items`: the defaults cover 1,024 items. The search chunker also limits
one document to about 1.6 million characters, so a larger document cannot be
imported whatever `max_text_kib` says.

Each refresh must also finish within `max_refresh_minutes` (default 5). The limit is
read when the refresh is queued, and that refresh keeps it. A refresh that runs past
that fails and publishes no new snapshot, and the source stops supplying specialists
until a complete refresh succeeds. Throughput has not been measured, so raise
`max_items` or `max_download_mib` only for a folder that one refresh can read in
that time.

## Starter corpora

`maverick knowledge seed` ingests a small, licensing-clean grounding corpus —
original plain-language summaries of public-domain frameworks (GDPR, EU AI Act,
NIST AI RMF, CCPA/CPRA), each anchored to the article it summarizes — into the
suite collections the shipped packs already point at. So a privacy/GRC
specialist can cite the governing regulation out of the box; customers layer
their own documents on top. Redistributable-restricted standards (e.g. ISO) are
deliberately excluded.

Reseeding reuses unchanged content. On SQLite and pgvector, a changed source is
embedded and validated before replacing its prior chunks in one transaction.
A provider failure or conflicting embedding identity leaves the accepted source
intact. Concurrent changes to that source require a retry. Replacement is atomic
per source; a seed command covering several sources is not one global transaction.

```
maverick knowledge seed --list          # show the shipped corpora
maverick knowledge seed                  # ingest them (keyless; idempotent)
maverick knowledge collections           # list collections + chunk counts
```
