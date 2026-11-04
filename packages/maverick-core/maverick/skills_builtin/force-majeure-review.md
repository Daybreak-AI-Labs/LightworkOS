---
name: force-majeure-review
triggers:
  - assess this force majeure claim
  - can the counterparty excuse performance here
  - does this act-of-god clause cover the disruption
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses whether a force-majeure or excuse-of-performance claim is supportable under a specific contract and its governing law. It parses the clause's triggering events, notice and mitigation duties, and consequences, tests the asserted event against them, and lays out the parties' options. Output is a force-majeure assessment with clause analysis, a supportability view, and staged next steps for counsel.

# Steps

1. Retrieve the contract's force-majeure clause and related provisions (notice, mitigation, termination, governing law) via `knowledge_search`. Quote the operative language verbatim; identify the governing-law jurisdiction, since FM doctrine and fallbacks (frustration, impossibility, impracticability) vary by it.
2. Break the clause into elements: enumerated triggering events plus any catch-all, the causation/"beyond reasonable control" standard, notice requirements (timing, form, content), the duty to mitigate, and the consequence (suspension, extension, termination, payment relief).
3. Test the asserted event against each element using the documented facts — was it enumerated or within the catch-all, was causation met, was notice timely and compliant, was mitigation attempted. Cite the clause text and any governing-law authority found; mark any element you cannot verify from the record as an open fact question.
4. State a supportability view (strong / arguable / weak) with the gating elements that drive it, and lay out options for each side (accept the excuse, dispute notice/causation, demand mitigation evidence, negotiate a standstill, reserve rights). Note common-law fallbacks only where the clause is silent and governing law allows.
5. Report the clause analysis, the element-by-element test, the supportability view, and the staged options. State assumptions and unverified facts explicitly and hand off to counsel; recommend a position only — do not declare the contract excused, terminated, or breached.

# Notes

The assessment is wrong if it treats FM as a generic standard rather than the specific contract's enumerated triggers, ignores governing-law doctrine, or assumes facts (notice given, mitigation attempted) not in the record — flag those as open questions, never fabricate them. A catch-all does not automatically cover foreseeable or economic-hardship events; say so. This is analysis, not legal advice: declaring performance excused or the contract terminated is irreversible and counsel-only. Do not use it without the actual clause text and governing-law identified, or to assess pure commercial hardship with no FM clause in play (that is a different doctrine).
