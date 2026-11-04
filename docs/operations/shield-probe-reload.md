# Optional Shield probe artifact reloads

The existing `shield.probe_model` setting or `MAVERICK_SHIELD_PROBE_MODEL`
selects a local plain-JSON linear classifier. This remains optional. The
built-in scan and heuristic score floor are unchanged. Reloading a classifier
does not establish better detection accuracy.

Each tenant and resolved path has independent bounded cache state. On the next
scan after five seconds, the loader reads at most 4 MiB and validates the entire
artifact before publishing one immutable model and its SHA-256 digest. Replacing
content at the same path is detected even when size and modification time are
preserved. At most 32 tenant/path entries are retained. Eviction causes a fresh
validation; it never reuses another tenant's model.

A missing or rejected artifact is retried on the next scan after two seconds.
If that tenant/path already had a valid model, the last known good object stays
active with `stale_rejected` status. Otherwise only the existing heuristic floor
is used and status is `unavailable`. Selecting a different path or disabling
the setting does not carry over a last known good model from another path.
Refresh intervals are cache policies, not filesystem I/O deadlines; use a local
regular file and atomically replace completed artifacts.

Operators can inspect current identity and reload state through
`maverick_shield.probe_model.configured_probe_status()`. It reports active digest,
schema/version, feature schema, rejected digest, a bounded reason and time until
the next eligible refresh. Paths and raw file contents are omitted. The function
uses the same refresh policy as scanning; it does not bypass validation.

Version 1 artifacts may declare `schema_version: 1`,
`feature_schema: "cheap-probe-features-v1"` and a bounded `artifact_version`.
Legacy plain weight files remain readable as schema 0, version `unversioned`.
Unknown schemas, duplicate JSON fields, nonfinite/boolean numbers, coefficients
outside ±1,000,000, thresholds outside [0,1], excessive weights, or invalid
n-gram parameters are rejected. There may be at most 65,536 weights/buckets and
1–8 n-gram sizes, each 1–32. Loaded weights are immutable.

Reloads keep the shipped red-team corpus's score and flag floor. That corpus is
a known regression corpus, not an independent held-out measurement of a newly
trained classifier.
Operators still need their own held-out quality evaluation before deploying
new weights; reloading does not authorize or perform model training.
