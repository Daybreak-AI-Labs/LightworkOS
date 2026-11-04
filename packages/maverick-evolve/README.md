# maverick-evolve

Governed, config-only evolution for Lightwork.

The package separates adaptive development search from adoption evidence:

- `eval_harness` evaluates immutable task snapshots with injected graders.
- `search` performs bounded config mutation and keeps a diverse archive.
- `metaproductive` is an experimental HGM-inspired search policy that treats a
  lineage's ability to produce useful descendants as a search signal.
- `runner` freezes one development champion and optionally compares it with the
  original seed on an independent sealed confirmation set.
- `adopt` performs lock-protected publication of a confirmed config.

This is not unrestricted self-code modification. Candidate mutation stays
inside the declared config space. Evolved code still requires an isolated
runtime, capability controls, independent evaluation, and human-governed
promotion.

## Risk-limited confirmation

`evolve_with_eval`, `evolve_metaproductive_with_eval`, and
`evolve_continuous` accept a sealed `confirmation_cases` snapshot. Adaptive
search never receives that snapshot or its scorer. Search fixes one champion,
then the seed and champion each receive one counterbalanced evaluation per
confirmation case. A tie, evaluator error, insufficient practical margin, or
non-positive uncertainty-adjusted paired lift keeps the seed.

Set `risk_limited=True` for the production-oriented contract. Before any
development evaluation it requires:

- sealed confirmation with at least 20 positive-weight cases by default;
- distinct positive-weight prompts after Unicode/whitespace normalization;
- a finite uncertainty threshold (`confirmation_confidence_z=1.96` by default);
- SHA-256 `confirmation_family_id` and `confirmation_evaluator_id` bindings; and
- a durable `confirmation_authorize(request)` callback that spends a
  pre-registered holdout query before either arm receives a sealed case.

The callback returns a short-lived `ConfirmationPermit` containing the exact
request digest, authorized critical value, authorization id, durable ledger tip,
and validity window. The request carries a fresh nonce plus both candidate ids,
the sealed-family/evaluator digests, and the distinct case count, so a receipt
cannot be replayed for another comparison. The runner uses the stricter of the
permit and configured thresholds. The family and evaluator identities must bind
the complete task/label manifest, grader implementation, model/system snapshots,
study epoch, and query policy; prompts alone are not an evaluator identity.
Continuous evolution defers archive publication until confirmation passes.
The exact evaluator's calibration receipt must contain at least 20 natural
correct/incorrect examples, is checked before exposure, and is checked again
after sealed evaluation before a champion can be returned for publication.

The non-risk path remains available for development compatibility. Its scores
must not be described as independent final-test evidence.

## Metaproductive development search

`evolve_metaproductive_with_eval` decouples expansion budget from exact
agent/case evaluation budget. It records each node/case observation at most
once, samples expansion parents from complete-clade Beta posteriors, prioritizes
under-evaluated nodes, and freezes the final development champion by a
conservative Wilson lower bound.

Outcomes are Bernoulli by default. `allow_fractional_outcomes=True` is an
explicit heuristic mode; its Beta/Wilson quantities are search scores, not
calibrated statistical evidence. A reused in-memory archive must be bound to an
explicit `case_family_id` covering evaluator semantics; archives without that
identity are deliberately non-resumable. Development case weights must be equal
because the current posterior samples tasks uniformly; unequal weights are
rejected rather than silently misrepresented. Duplicate or failed mutations
still consume expansion budget, and tree/evidence inconsistencies fail closed.

Clade observations overlap, so their posteriors are correlated. The policy is
an exploration heuristic inspired by HGM, not a reproduction of HGM and not
promotion proof. The ordinary sealed confirmation boundary remains mandatory
for adoption.

## Integrity boundaries

- Archive envelopes use canonical JSON, full SHA-256 identities/checksums, size
  bounds, finite numeric validation, and strict schema/version handling.
- Resumed scores are observations only; active runs revalidate candidates and
  reject configs outside the declared capability/config envelope.
- Calibration backend errors freeze evolution. Risk-limited mode additionally
  requires a fresh, evaluator-bound, internally coherent positive receipt,
  applies its sample floor to the natural cohort rather than probe-inflated
  totals, and never honors the `MAVERICK_LEARNING_FROZEN=0` development override.
- Same-process adoption is serialized, and cross-process publication relies on
  the shared strict file-locking layer.

The local archive confirmation marker is checksummed and durably revoked before
resumed revalidation, but it is not a signed, externally anchored, expiring
promotion receipt. Adoption therefore remains an explicit operator action.

These controls establish protocol behavior, not a measured improvement over
other methods.

## Evaluation execution evidence

`evaluate` retains an `EvalObservation` for every completed exposure: execution
status, optional answer grade, bounded diagnostic category, visible-case digest
and evaluator identity. `evaluate_case` remains a float-returning compatibility
API; `observe_case` exposes the typed result. A crashed, timed-out or non-string
execution is never sent to the rubric and contributes zero development fitness.
A successful empty answer or abstention is still graded normally. A custom
evaluator without an explicit identity is labeled unversioned; hashing visible
case fields does not claim to version arbitrary Python check code.

Sealed confirmation rejects the comparison if either arm has any execution
failure. Ordinary failures still consume exactly the existing counterbalanced
one-exposure-per-arm schedule; there are no retries. Cancellation, budget,
accounting and halt signals stop immediately and propagate, so unused exposures
are not spent. The existing durable permit remains consumed even when evaluation
fails. Evaluator exceptions and invalid grades reject confirmation as before.

Structured operational log messages link case/status observations to comparison,
candidate and exposure IDs, including cancellation. They exclude prompts,
answers, exception messages and sealed grades. These logs are diagnostic evidence,
not a new durable receipt store. Deployments must retain their configured logs
to retain these diagnostics. Existing archives and historical scores are not
rewritten or relabeled as revalidated evidence.
