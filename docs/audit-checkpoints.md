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

Run publication on a short, risk-appropriate schedule and after
security-sensitive changes. Checkpoints complement rather than replace
closed-day WORM export.
