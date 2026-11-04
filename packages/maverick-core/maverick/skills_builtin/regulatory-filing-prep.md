---
name: regulatory-filing-prep
triggers:
  - prepare a regulatory filing
  - regulatory submission package
  - filing prep for a regulator
tools_needed:
  - knowledge_search
---
# What this skill does

Assembles a regulatory filing package for a specific filing type and regulator. Produces a completeness checklist (every required form, attestation, and exhibit) plus the matched supporting exhibits, ready for a compliance owner to review and submit.

# Steps

1. Identify the exact filing (regulator, form/regulation, reporting period, deadline) from knowledge_search. If the filing type or jurisdiction is ambiguous, stop and confirm — requirements differ by regulator and version.
2. Retrieve the authoritative requirements checklist for that filing via knowledge_search (required sections, schedules, signatures/attestations, format). Cite the source regulation/instruction for each line item; mark any requirement you could not source as unverified.
3. Map available internal documents/data to each checklist item as supporting exhibits. Flag every gap (missing exhibit, stale data, unsigned attestation) explicitly rather than treating it as satisfied.
4. Hand off the package: the checklist with pass/gap status, the matched exhibits, and the submission deadline — marked DRAFT FOR COMPLIANCE REVIEW, stating assumptions and all unresolved gaps.

# Notes

The package is wrong if a requirement is sourced from a superseded version of the regulation, or if a gap is silently filled with an inferred value — both create filing risk. This skill prepares and recommends only; signing, certifying, and submitting to the regulator are irreversible and must be done by an authorized human filer. Do not use it to submit, and do not use it when the filing's governing regulation/version cannot be confirmed.
