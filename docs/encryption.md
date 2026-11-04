# Encryption at rest

Lightwork keeps its state under `~/.maverick`. By default that state is plaintext on
disk — fine for a personal agent, but a GDPR Art. 32 / HIPAA exposure once the agent
handles sensitive data. **At-rest encryption** seals the sensitive stores with
AES-256-GCM.

## Enable it

**On by default** (secure-by-default). The key auto-generates on first use, so
new writes are sealed with no configuration — see
[Back up the key](#key-management) immediately, because losing it loses the data.

Resolution (first match wins): a compliance floor (e.g. HIPAA) forces it on >
`MAVERICK_ENCRYPT_AT_REST` env > `[encryption] at_rest` in config > enterprise
mode > the secure-by-default switch (on). To **disable** it on a personal box:

```toml
[encryption]
at_rest = false
```

- env: `MAVERICK_ENCRYPT_AT_REST=0`
- or turn off the whole secure-by-default posture with
  `MAVERICK_SECURE_DEFAULT=0` / `[security] secure_defaults = false`
  (see the [security and compliance overview](enterprise/security-overview.md)).

Existing installs are safe to leave on: reads are plaintext-tolerant, so rows
written before it was enabled are returned unchanged until rewritten (run
`maverick encryption migrate` to seal them eagerly).

## What gets sealed

| Store | Location | Field(s) |
|---|---|---|
| Cross-session memory | `~/.maverick/memory/**` | whole files |
| Channel conversation turns | world DB | `turns.content` |
| Persisted facts | world DB | `facts.value` |
| Per-goal agent message log | world DB | `messages.content` |
| Clarifying questions | world DB | `questions.question`, `questions.answer` |
| Goal content | world DB | `goals.title`, `goals.description`, `goals.result` |
| Per-agent goal events | world DB | `goal_events.content` |
| Episode summaries | world DB | `episodes.summary`, `episodes.outcome` |
| Parked approvals | world DB | `approvals.action`, `approvals.scope`, `approvals.detail` |
| Semantic-recall documents | `vector_store` (chroma/pgvector) | sealed document; vector from plaintext |
| Attachments | `~/.maverick/attachments/**` and the S3 mirror | whole files, bound to tenant + goal + stored name |

Sealing is transparent — values are encrypted on write and decrypted on read, so
application behaviour is unchanged. A value written **before** encryption was enabled
carries no seal marker and is read back as-is, so enabling encryption is a gradual
migration, not a flag-day re-encrypt.

**Context binding.** Attachments are sealed with the tenant and their
`attachment/<goal>/<stored name>` identity as authenticated data: a sealed file
copied to another goal, name or tenant fails GCM authentication rather than
decrypting there. Content addresses (sha256) remain those of the plaintext, the
S3 mirror stores the same sealed bytes under a tenant-scoped key
(`<prefix><tenant>/<goal>/<name>`, falling back to the pre-scoping key for older
objects), and files written before sealing stay readable. Downloads of sealed
files are decrypted in full (bounded by the attachment size cap) because GCM
authenticates the whole blob before releasing plaintext; external tools
(transcription, document extraction) receive a private temporary plaintext copy
that is removed afterwards.

World-model columns are not context-bound yet: in per-tenant mode a sealed value
is bound to its tenant, but within one tenant a sealed value copied to another
row or column still opens. Binding each field to its row needs the row id at
write time, which the insert paths do not have; treat database write access as
able to rearrange sealed values within a tenant.

**Per-tenant keys** (`[encryption] per_tenant`, off by default) give each
tenant its own data key. A tenant data key is generated and wrapped on the host
that first needs it, so it is not shared between replicas: attachments are
therefore always sealed with the deployment (or keyring) key, with the tenant
bound as authenticated data, so the S3 mirror opens on every replica that
shares that key. The tenant id is bound in its canonical (NFC) form.

## Seal existing data

To seal data written *before* encryption was enabled (instead of waiting for it
to be rewritten), run:

```
maverick encryption migrate           # seal existing turns/facts/messages/questions
maverick encryption migrate --dry-run # report how much would be sealed
maverick encryption migrate --backup  # opt in to a plaintext rollback snapshot
```

It is **idempotent** (already-sealed values are skipped, so it is safe to re-run)
and requires at-rest encryption to be enabled first.

**Backups are opt-in:** the reseal happens *in place* and shreds the
pre-encryption plaintext residue (`secure_delete` + VACUUM). By default the
command does **not** leave a plaintext rollback copy on disk. If your rollback
plan requires one, pass `--backup` to write a transactionally-consistent snapshot
of the DB next to it — `world.db.pre-encrypt-<timestamp>.bak`, mode `0600`. That
snapshot is a **plaintext** copy (it predates the seal), so store and delete it
according to your data-retention policy once you have verified the migration.
The backup is skipped on `--dry-run` and when there is nothing left to seal (so
idempotent re-runs don't litter copies).

## Key management

Key resolution (first match wins):

1. `MAVERICK_ENCRYPTION_KEY` — a 32-byte key as hex or base64, e.g. injected from a
   KMS / secrets manager so it never touches disk.
2. `~/.maverick/keys/at_rest.key` — generated on first use, `chmod 600` inside a
   `chmod 700` directory.

**Fail-closed:** if encryption is enabled but the `cryptography` backend or the key is
unavailable, a write *errors* rather than silently storing plaintext.

**Back up the key — losing it loses the data.** The key file is the only way to
read data sealed under it; if it is lost, that data is unrecoverable. At-rest is
on by default, so the key auto-generates on first use (with a one-time warning).
Escrow it immediately into a secrets manager / offline vault:

```
maverick encryption backup-key --to /secure/escrow   # copies at_rest.key + keyring keys (0600)
```

Store the copies at least as well-protected as the originals, and not next to the
data they unlock. Operators who inject `MAVERICK_ENCRYPTION_KEY` already hold the
key in their secrets manager and need no on-disk backup.

`maverick backup create` (like `maverick client export`) leaves the raw key files out of
the archive: the at-rest key and keyring and the audit signing keys, those of the data
root and of every workspace under `tenants/<id>/`. `backup create` lists the files it
left out when it finishes. The escrow copy above is then the only copy of the encryption
keys, unless you pass `--include-keys` to bundle them.

**Backend:** both backends seal the same sensitive content columns through the
shared field-sealing path, so selecting Postgres (`[world_model] backend =
"postgres"` / `MAVERICK_WORLD_BACKEND`) keeps content encrypted at rest. Postgres
additionally needs TLS to the database (`sslmode=verify-full`, see
`deploy/postgres/README.md`) to protect data in transit.

## Search trade-off

`messages.content` is full-text indexed (SQLite FTS5). Under encryption the index
holds ciphertext, so a plaintext query can't match it — **full-text search over
encrypted messages is disabled** (messages written before encryption stay searchable).
The `facts` substring search (`search_facts`) likewise can't match encrypted *values*;
key matches still work.

## What is *not* sealed (and why)

- **The audit log** (`~/.maverick/audit/*.ndjson`) — integrity comes from the Ed25519
  hash-chain plus the erase/retention tooling. **Closed** day-files can be sealed at
  rest with `maverick audit seal`; the **current** day-file stays plaintext for the
  live append + signing path, so there is a confidentiality window on today's file
  until it rolls and is sealed. Secrets in audit payloads are redacted before write
  regardless.
- **The semantic-recall vector store** (`~/.maverick/vector_store/**` and external
  chroma/qdrant/weaviate/pgvector) — under at-rest encryption the stored document
  **is sealed** for the **chroma** and **pgvector** backends: the query/goal text is
  embedded client-side (local all-MiniLM) from the plaintext and only the *sealed*
  document + the vector are stored, so similarity search still works while no
  verbatim text lives in the store (a separate `_s` collection keeps sealed data
  apart from any legacy plaintext-embedded vectors — re-indexing repopulates it).
  The **qdrant**/**weaviate** backends embed server-side, so the sealed path isn't
  wired for them yet: under at-rest the semantic path is **disabled** for those two
  (it falls back to lexical recall over the sealed world DB rather than ship them
  plaintext). With at-rest off, behaviour is unchanged. Metadata never carries the
  sensitive `title`/`result` on any backend (hydrated from the sealed DB by
  `goal_id`).
- **`config.toml` / `.env`** — configuration and API keys; `.env` is already
  `chmod 600`. Protect these with filesystem permissions / full-disk encryption.

## Verify

`maverick compliance` reports the at-rest control under **GDPR Art. 32**.
