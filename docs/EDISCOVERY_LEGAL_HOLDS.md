# Legal holds and matter export (eDiscovery)

A **legal matter** holds the records of named people for a legal dispute. It is
off by default. Turn it on with:

```toml
[ediscovery]
enable = true
```

The setup wizard asks the same question ("Legal holds and matter export?"), and
the settings page lists it under Privacy. When the switch is off, there are no
matter routes, no Legal holds section, and no matter records. A matter recorded
while the switch was on keeps working as a hold until it is released, even if the
switch is later turned off.

## Who can manage matters

Creating, viewing, editing, releasing and exporting a matter need the **audit**
permission. The administrator role holds it too. Viewers and operators get a
refusal. The Legal holds section appears on the **Compliance** page only for people
with audit access.

## What a matter holds

| Field | Meaning |
| --- | --- |
| Name, description | Shown to people with audit access only. |
| Custodians | Principal ids, one per line: `user:<name>` for a dashboard user, or `user:<channel>:<identifier>` for a messaging account (for example `user:cli:local` for the local command line). A linked messaging account is written exactly as `account:<hash>:person:<hash>` (see below). A bare name is refused. |
| From / To (optional) | Calendar dates in UTC. Both ends are inclusive. |
| Records to keep | Any of: tasks and their runs, chat conversations (including employee companion history and conversation-inbox messages), attachments (including incident attachments the custodian uploaded), approval requests. |
| Status | `active` or `released`. Releasing is final for that matter and is audited. |

### Linked messaging accounts

A person who links a Slack, Teams, Telegram or other messaging account has that
account's chats stored under the account's identity, `account:<hash>:person:<hash>`.
Room and thread histories add `:conversation:<hash>` to it. Name the account as
the custodian, written exactly in that form with 64 lowercase hexadecimal characters
in each hash. The matter then holds:

- every chat of that account on every channel, including each room and thread;
- the tasks owned by that account on each messaging channel, and their runs,
  attachments and approvals.

Any other text is not that account. A custodian with a different hash, a longer
identifier that only starts with the same text, or a `user:<channel>:account:` form is
refused or not matched. Companion history and conversation-inbox messages belong to
dashboard users, not to channel accounts. To hold those, name the dashboard user as well.

For its tasks and runs, a linked account adds one lookup on each messaging channel, and
each check reads the workspace's chat list once. A matter with many linked accounts
therefore takes longer to check. Measured on a local SQLite workspace, 500 account custodians took about
1 second per check (2.5 seconds with 20,000 other conversations), and 50 took about a
tenth of a second. Shared (Postgres) databases were not measured.

To find an account's identity, an administrator opens **Compliance** and goes to
**A person's data**. The **Person** list shows each linked account as
`account:<hash>:person:<hash>`, followed by `:conversation:` for room and thread
histories. Copy the text up to the second hash.

Every create, edit, release, export, and every reading of matter details writes an
audit event that records the matter ID, who acted, the revision and which fields
changed. Audit events never name the custodians or the matter definition. A change
is saved only when its audit event is written, and matter details are not shown
when the reading cannot be recorded.

The list shows at most 500 matters. When there are more, the page says so. Every
active matter still applies, including the ones not listed.

## What an active matter blocks

**Bulk deletion of old records is paused for the whole workspace.** This covers
retention enforcement, `maverick gc`, the dashboard "Tidy up old records" action,
the all-workspaces clean-up, and the retention review (which shows the workspace as
blocked). Any active matter blocks these, because the stores cannot reliably tell
which records belong to which custodian. A privacy-rights case hold recorded for the
workspace (a legal hold, or a retention block on a privacy request) pauses the same
actions. If the privacy-rights records cannot be read, the actions pause too. The
all-workspaces clean-up skips such a workspace and reports it as held. Whole-client
erasure and the erasure of a removed workspace are also refused while a matter is
active.

**Erasing a person is refused only for records in scope.** A closure is refused
when it contains a record that is in the matter's:

- custodians (the record's owner is a custodian, or the conversation belongs to one),
- record types, and
- date range (see below).

Records outside the scope stay erasable: other people's records, and records
outside the date range. The refusal says only that a legal hold applies to some of
these records. It never names the matter.

Each of these paths applies the check:

- `maverick erase` (command line) and the admin "erase a person" action, for channel
  conversations. The command line rule for local sessions is shared with the matter
  check, so a hold on `user:cli:local` covers every local session.
- Reviewed deletion requests (privacy requests) for conversation history, companion
  history and conversation-inbox messages. A request holding anything is reported as
  **held**, and nothing in it is erased. The inbox checks every message before it
  erases the first, so a refusal never leaves a partial erasure.
- An employee clearing their own companion conversation, the companion history
  route, and disabling a companion. Disabling keeps any exchange a matter holds in
  scope, and the companion's retention clock never removes one either.
- Deleting or changing an incident attachment (only its uploader can do either), and
  the retention purge of incident attachment records. A held attachment is refused, or
  skipped by the purge, until the matter is released.
- Erasing a removed workspace (its whole tree), and whole-client erasure.

### Date rules

Each record is tested against its own timestamp:

- task: creation time; run: start time;
- chat: any turn in the range (a conversation with no turn in the range is out of scope);
- companion exchange: the time it was saved;
- conversation-inbox message: the time it was created;
- attachment and incident attachment: upload time;
- approval request: request time.

A closure that mixes in-scope and out-of-scope records is refused as a whole. A
partial erasure is never performed.

If a matter's records cannot be listed completely (more than 100,000 records of one
kind), the erasure is refused. The check fails closed. The same applies when the
matter ledger cannot be read.

## Export

An auditor exports a matter as a ZIP archive:

- `goals.jsonl`, `chats.jsonl`, `attachments.jsonl`, `approvals.jsonl`: one file per
  selected record type, holding only the in-scope records, one JSON object per line.
  `chats.jsonl` holds conversation turns, companion exchanges and inbox messages,
  each marked with its `record_type`. `attachments.jsonl` holds the attachment rows
  and the incident attachment metadata rows (`record_type` `incident_attachment`),
  never the file bytes. An incident attachment row names its uploader only by the
  stored one-way reference.
- `manifest.json`: the matter definition, the SHA-256 and size of every file, the
  record counts, what is not included, and a signature.

The signature uses the workspace's audit signing identity (Ed25519 over a
domain-separated SHA-256 of the canonical manifest). It is the same signature used
for other exports. The signature proves the archive was produced by this
installation and has not changed since. It does not prove who requested it.

The archive is written as a ZIP entry by entry, and it is deleted once its download
ends, however that ends. An export that never finished (for example, the process
stopped) is removed the next time an export runs, once it is more than an hour old.

The export is refused with a message to narrow the matter when its records would
exceed 256 MiB. That limit counts the uncompressed JSONL lines; the manifest and the
compressed archive size are not counted. The export is audited. If the audit record
cannot be written, no archive is released.

To check an archive offline, use `maverick.ediscovery_export.verify_export` with
the audit public keys. It recomputes the manifest digest, checks the signature
against the audit key registry, and checks every file's size, hash and record count.
Any entry that is missing, extra or changed is reported by name.

The in-scope records are collected in memory before the archive is written. Each
source list is limited to 100,000 records; a larger matter is refused rather than
exported partly.

## Integrity of the matter ledger

Each matter record carries a SHA-256 digest of its own contents. The digest catches
accidental or partial damage to the ledger file. It does not stop someone who can
write the ledger, because they can recompute it. The export signature is the
tamper evidence for an export.

## What is not covered

- **Linked messaging accounts named by a dashboard user.** A custodian `user:<name>`
  does not reach a linked account's chats, which are held only when the account
  itself is named (see above). Name each account the matter covers.
- **Unsent drafts, derived memory and other copies of chat text.** Recovery drafts,
  personal recall notes and similar derived stores are not part of a matter.
- **Attachment file bytes** are not copied into the archive. Each attachment row has
  its SHA-256 and size. The files stay in their own store, and a matter does not change
  them. Only the metadata rows of incident attachments are held. Their file bytes are
  kept in the governed document vault, which does not check matters. Once an
  administrator revokes the document and its retention period ends, the vault can purge
  the bytes even while a matter holds the metadata row. The held row keeps the document
  identity, size and digest, but the file itself may then be gone. If a workspace holds
  more than 10,000 incident attachment records, a matter that keeps attachments cannot
  be exported, and the export says so.
- **Audit evidence, knowledge-base copies, model memory, backups and copies held by
  outside providers** are outside the matter. A matter does not change their retention.
- **Approvals** are never deleted by any erasure path, so no erasure is refused for
  them. They are held in the export only.
- **Direct database calls** to the world-model erase primitive do not check matters
  themselves. Every product path listed above does.
- **Mixed closures** are refused whole. There is no partial erasure to keep out-of-scope
  records while in-scope ones stay.
- **Timing.** The hold check runs just before a deletion. The ledger is a separate
  database, so a matter created while a deletion is already running is not seen by
  that deletion. The next check sees it.

## Releasing a hold

Open the matter in the Legal holds section, choose **Release this hold**, and confirm.
Released matters no longer block anything. Their records and audit history remain.
