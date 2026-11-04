# Governed Knowledge

Governed Knowledge is the in-app organizational-memory boundary at
`/knowledge-access`. It displays and exports only exact dataset versions in the
research registry. A label, search hit, cached summary, or caller-supplied source
description is never enough to admit content.

Enable or disable the surface in the installer or configuration:

```toml
[knowledge_access]
enable = true
```

`MAVERICK_KNOWLEDGE_ACCESS=0` is the deployment override. Existing installations
without the section remain enabled for compatibility. An unreadable or malformed
active configuration disables the surface.

## What is checked

Before every search result, detail view, cache hit, export item, and worker
materialization, Lightwork resolves:

1. the authenticated named actor and selected tenant;
2. the requested purpose and exact action;
3. the exact dataset asset, version, and manifest SHA-256;
4. current registry approval, source checksum, license, and usage constraints;
5. current data-use expiry and optional consent authority; and
6. every parent dataset with the same requested action.

`read` means human-readable display. An authority reviewed for analysis or export
may permit that narrower display. Training-only authority does not permit display.
Export and training remain exact actions. Constraints such as
`no_human_display`, `training_only`, `no_export`, or
`separate_training_permission_required` further narrow use.

The in-process cache stores a bounded summary keyed by tenant and exact registry
version. Eligibility is never cached, and the owning store is re-read to verify
the exact content commitment even on a cache hit. A failed current check evicts
the summary, and the UI clears its result and export selection immediately.

## Search, continuation, and evidence

Search filters the selected tenant and assigned source/collection boundaries before
its bounded candidate window. Unrelated newer registry versions cannot displace an
older assigned source. Each page examines at most 250 selected exact versions and
ranks their currently authorized title, summary, and asset terms with a local
lexical BM25 baseline. Question words and common English inflections are normalized;
this is lexical retrieval, not a claim of semantic or model-answer accuracy.

Results explicitly distinguish `matched`, `no_match`, `incomplete`, and
`unavailable`. `matched` counts matches **within the candidate page**, and ranking
is within that page, not across unexamined sources. `complete=false` and
`incomplete_reasons` identify more matches, more candidate versions, or content that
could not be checked. An empty incomplete page does not establish that evidence is
absent. Source outages remain visible across continuation pages.

The Knowledge page offers **Next results** when a continuation exists; it replaces
the displayed page and clears prepared detail/review state. Every continuation
rechecks current authority and source content. Editing the query, intended use, or
limit discards the continuation and ignores an outstanding response for the older
search. API clients use the returned `next_cursor` as `cursor` with the original
query, purpose and limit. Agent `knowledge_search` callers also retain the same
query and `k`. Cursors are bounded query-position hints, not authorization. Later
registry additions are excluded from that search snapshot; changed rankings within
an unfinished page require restarting instead of silently skipping or repeating
matches. Revoked sources and parents can never be restored by a cursor.

The lexical projection cache is bounded and keyed by tenant, exact reference,
source-content digest and projected text. It caches derived terms, not permissions;
the owning source is reread even on a cache hit. The agent path rematerializes the
selected exact versions at job start before returning text.

Agent evidence uses `lightwork.knowledge-evidence.v1`: each passage retains its
source, asset, exact version, manifest and content digests, provenance kind,
inferred/verified claim state, observation/verification UTC dates, and correction
states. A null date means unknown. Conflicting passages remain separate. Excerpts
are bounded and explicitly marked when shortened. Permission to use a source is
kept distinct from factual certainty; source metadata and excerpts are quoted data.

## Existing-store source references

The installed projector currently supports these exact references:

- `catalog:evidence-graph/<node-id>` for a current approved evidence node;
- `catalog:fleet-memory/<immutable-file>.json` for one immutable, screened fleet
  inbox record;
- `catalog:vector-knowledge/<collection>/<document-sha256>` for one complete
  ingested document whose chunks retain unique positions and a complete count;
- `catalog:work-discovery/<owner-base64url>/<device>/candidates` for exact
  content-free Ekko candidates under the owner's live control authorities; and
- `catalog:knowledge-correction/<request-id>` for an immutable correction
  prepared by the rights-request workflow.

The projector canonicalizes the exact store record and requires its SHA-256 to
match the dataset version's `content_sha256`. In the Research lab, an installation
administrator can enter a built-in reference and leave Content SHA-256 blank;
Lightwork reads that exact installed record and binds the canonical checksum into
the draft. Use the same in-app workflow to review and approve it. An unsupported
store, missing record, stale evidence node, disabled owning feature, checksum
mismatch, legacy vector row without a complete ordering commitment, or ambiguous
duplicate document is unavailable. Vector similarity order is never used for
reconstruction. The Ekko projector uses its public store method while deployment,
consent, device, and session authorities remain locked. The encoded owner must
exactly match the currently authorized actor, and training use is withheld.

## Corrections, exclusions, and deletion

An installation administrator can submit and decide a request against the exact
source version. The record stores the derivative list reviewed at submission and
re-walks current registry lineage for every later view. Approval retires the
source version from new use and records required dataset invalidation or model
retirement/retraining follow-up.

An approved correction first registers and independently approves a deterministic
replacement version whose immutable source binds the request, prior version, prior
checksum, requester, and corrected text. Only then does it retire the prior version.
The request exposes the exact replacement reference and never reports completion
while the replacement is pending. The requester and replacement approver must be
different named users.

A deletion request can carry one governed retention hold. The hold records its own
identity, basis, evidence digest, placing actor, placement time, and required expiry.
It can be released only by a named user with a new reason and evidence digest. An
active hold records that preservation is required while allowing the exact registry
version to be retired from new use. Because the owning source may be external, the
workflow reports preservation as unverified instead of claiming it happened. Hold
expiry is shown separately from a recorded release.

If the process stops after an approval enters `applying`, the Request status card
offers recovery. The same named reviewer re-enters the exact prior rationale. Its
SHA-256, decision, and current request revision must match before Lightwork
finishes the durable transition.

Deleting or excluding a raw record does not prove that its influence has been
removed from learned weights. The UI and export preserve that limitation.
External store availability, installed-system behavior, customer acceptance, and
model retirement or retraining are not qualified; verify them in your
environment.
