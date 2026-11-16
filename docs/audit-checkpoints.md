# Independent audit checkpoints

Lightwork's signed row chain proves that the rows still present are authentic
and ordered. It cannot prove that somebody did not remove a valid signed
suffix. Closed day-files have the signed anchor ledger and optional WORM
export. Checkpoints provide an independently retainable commitment while a day
is live and for any other day that needs an additional custody boundary.

Publish a commitment:

```console
maverick audit checkpoint publish \
  --checkpoint-dir /mnt/independent-audit-checkpoints
```

The destination must be disjoint from the audit directory. For independent
assurance, put it under a separate account, WORM policy, SIEM, transparency
service, or equivalent control. A second writable directory on the application
host improves fault detection but is not an independent trust anchor.

Each numbered checkpoint is:

- a complete, one-row Ed25519-signed evidence file;
- part of a monotonically numbered digest chain over the preceding file's
  exact bytes;
- a commitment to one audit day's signed row count and exact tip hash; and
- staged, flushed, verified, and atomically exposed only after it is complete.

Publication and retirement take the audit day's strict sidecar lock before
reading the signed anchor ledger and taking the checkpoint-index lock. Audit
append, retention, and GDPR rewrite paths use that same day sidecar. The
ordering is always `audit day -> anchor ledger -> checkpoint index`; no path
takes those locks in reverse. Snapshot verification, lifecycle evidence,
same-era comparison, signing, and publication therefore observe one stable day
state without a deadlock cycle.

## Independent verification

Retain both the printed sequence and SHA-256 outside the checkpoint directory,
then verify with the exact allowed signer set:

```console
maverick audit checkpoint verify \
  --checkpoint-dir /mnt/independent-audit-checkpoints \
  --minimum-sequence 184 \
  --minimum-digest 7f0b...64-hex-characters...9c \
  --pubkey "$OLD_AUDIT_PUBLIC_KEY" \
  --pubkey "$CURRENT_AUDIT_PUBLIC_KEY"
```

`--pubkey` is repeatable so an explicit pinned set can cover a controlled key
rotation. A row signed by any key outside that set fails verification. A new
checkpoint is also refused when the active signer is outside the supplied set.
The minimum sequence detects rollback; the digest detects a signed fork at the
externally retained sequence.

A retained sequence also fixes what "verified" means for each day it covers.
A supersession starts a new era for a day and a retirement ends its
comparison with the log (see below). Both are signed with the same key as
the log, so whoever holds that key could otherwise replace or drop a
commitment you had already retained. With `--minimum-sequence`, verification
therefore fails for every supersession and retirement published after that
sequence and names the day:

- `retired_after_pin`: the day-file is gone and its checkpoint was retired.
  Check that this was a retention purge you expected and not a day that
  should still be there, then retain the newest sequence and digest
  (`maverick audit checkpoint retire` prints them).

- `superseded_after_pin`: a stored erase record matches the change. The
  line gives its erasure id and row count, and the ids of any earlier
  erasures of that day on file (not their rows: an earlier erasure may have
  been undone by a restore since). Match that
  id against an erasure request you know about, then retain the newest
  sequence and digest; the check is clean again from there. The record is
  not proof on its own (see "What an erase record proves").
- `superseded_without_erase_record`: no stored erase record matches the day
  as it is now. It was published with `--without-erase-record` (the activity
  log then holds an `audit_checkpoint_publish_without_erase_record` entry),
  by an earlier version, or by someone holding the signing key. Compare the
  day with a copy kept elsewhere before you retain anything newer.
- `superseded_erase_record_unchecked`: the erase records could not be read.
  Run the check where the world model is available.
- `superseded_then_replaced`: the day was replaced or retired again
  afterwards, so this record can no longer be compared with the log. The
  later record is reported on its own line; judge the day by that one.

Without `--minimum-sequence` there is no retained point to compare with, and
supersessions and retirements are checked only for their signed lifecycle
evidence, as before. A scheduled check that keeps an old sequence will fail
after each retention purge until it retains a newer one.

Verification never creates a lock file, changes a mode or ACL, or writes to the
audit or checkpoint store. It can run against read-only media. All commitments
for the same day are checked with one day-file scan.

A successful check without an explicit public-key set, minimum sequence, and
minimum digest is reported as *internally consistent*, not independently
anchored. Keep those external values if the result will support a compliance or
forensic assurance claim.

## Authorized lifecycle changes

A GDPR re-anchor changes signed row hashes, while retention removes a day-file.
Neither should be silently reported as clean, and neither should permanently
break verification after an authorized operation. Checkpoints therefore use
signed, explicit lifecycle records:

- Default publication refuses a row-count regression or changed historical
  prefix.
- After an authorized GDPR rewrite, publish with
  `--lifecycle-reason gdpr_reanchor` and
  `--supersede-digest <latest-checkpoint-sha256>`. Lightwork requires matching
  signed re-anchor evidence or, for a live day, a signed erase marker that
  names the exact superseded checkpoint digest. Lightwork binds that evidence
  and the exact superseded checkpoint into the new signed record.
- That evidence is signed with the audit key, so the key's holder can produce
  it alone. Publication therefore also requires an erase record: `maverick
  erase` stores one in the world model's receipt table for each audit day it
  rewrites, with the day, its row counts and its new tip hash and nothing
  about the person. The day being published must still contain
  that tip, and the record must list the checkpoint being replaced and be
  newer than it, so one erasure cannot explain a later change. The override below
  writes an activity-log entry naming who ran it and the day before it
  publishes, and publishes nothing if that entry cannot be written.
- `maverick erase` compares each day it is about to rewrite with the
  checkpoint folders this installation knows (beside the log, the custody
  store, and the folder chosen in the checkpoint settings) and any named
  with `maverick erase --checkpoint-dir`. The erase record lists the
  checkpoints the day still matched, or that an earlier erasure's record
  accounts for, and only a listed checkpoint can be replaced on that
  record. A day that differs from its checkpoint for any other reason is
  still erased, since a person must always be erasable, but its checkpoint
  is left off the list. So a genuine erasure cannot cover a change nobody
  recorded, and an erasure that never saw a checkpoint folder cannot
  replace its checkpoints.
- When no record lists the checkpoint (a day erased before erase records
  existed, or one of the cases above), replace it with
  `--without-erase-record`, or on the activity-log page with "Replace it
  without an erasure record". Anyone verifying against an older retained
  sequence then sees `superseded_without_erase_record` for that day. Only a
  day with fewer rows than its checkpoint still stops an erase.
- After signed retention has removed a day, retire its latest commitment:

```console
maverick audit checkpoint retire \
  --checkpoint-dir /mnt/independent-audit-checkpoints \
  --lifecycle-reason retention_purge \
  --supersede-digest <latest-checkpoint-sha256>
```

Retirement is accepted only when the signed retention ledger names the exact
day, row count, and tip committed by the checkpoint. Prior evidence remains
immutable; the lifecycle record explains why it is no longer compared with the
current filesystem.

## What an erase record proves

An erase record is a row in the world model's receipt table, signed with the
audit key. The table refuses updates and early deletes, but it accepts an
insert from anything that can write the world model, on SQLite and on
Postgres alike, and nothing checks that an erasure took place.

- It shows that something holding the signing key and write access to the
  world model recorded an erasure of that day, with those row counts.
- It does not show that anyone asked for the erasure, that the erased rows
  were the person's, or that nothing else in the day changed. Someone with
  both the key and the database can store one for a change of their own.
- An honest `maverick erase` narrows the last point: its record backs
  replacing only the checkpoints the day still matched when it ran.

The control is the report, not the record: every supersession and retirement
published after your retained sequence is shown to you, with or without an
erase record, until you retain a newer sequence. Keep that sequence and digest
where the installation cannot change them, and review each reported day
against what you know was erased or deleted.

Run publication on a short, risk-appropriate schedule and after
security-sensitive changes. Checkpoints complement rather than replace
closed-day WORM export.
