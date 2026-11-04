---
name: citation-shepardize-verify
triggers:
  - shepardize
  - check if still good law
  - verify citation treatment
  - validate legal citations
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

This skill verifies the legal authorities cited in a brief or memo two ways: that each citation points to a real, correctly-quoted source, and that the authority is still good law by checking its subsequent treatment (overruled, reversed, abrogated, superseded, questioned, or distinguished). It exists specifically to catch hallucinated or stale citations before they reach a court. Any authority that cannot be confirmed against a real source is marked [UNVERIFIED] and excluded from reliance — the skill never asserts a case is good law on inference. The output is a citation table with treatment status and an [UNVERIFIED] list, staged for the attorney; it does not file or sign anything.

# Steps

1. Use read_file to extract every citation from the document — cases, statutes, regulations — with the exact pin cites and any propositions the brief attributes to each authority.
2. For each authority, confirm it exists and says what the brief claims by locating the real source (via knowledge_search against a verified case/statute library or an authorized legal database). Verify the quoted language and the pin cite. If you cannot locate a genuine source for a citation, mark it [UNVERIFIED] — do not treat plausibility as confirmation.
3. For each confirmed authority, check its subsequent treatment: has it been overruled, reversed, abrogated, superseded by statute, or its reasoning questioned/distinguished? Record the treatment signal and the citing authority. Flag any negative treatment that undercuts the proposition it is cited for.
4. Assemble the citation table (citation, exists?, quote verified?, treatment status, negative-treatment notes) plus a separate [UNVERIFIED] list and a "no-longer-good-law" list, and stage it for the attorney. Mark that reliance, removal, and filing decisions are the attorney's.

# Notes

Hallucinated citations are the core risk this skill guards against — courts have sanctioned filings with fabricated cases, so anything you cannot confirm against a real source is [UNVERIFIED] and must not be relied on; never paper over a gap by asserting the case "appears to" support the point. "Exists and is quoted correctly" and "is still good law" are two separate checks — a real case can be overruled; do both. Treatment signals are nuanced: distinguished is not overruled, and a statute can be superseded without any case saying so — describe the treatment, don't collapse it to good/bad. This skill verifies and flags; it does not file, sign, or decide what to cite — that stays with the attorney. Keep a source link for every confirmed cite so the attorney can independently check.
