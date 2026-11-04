---
name: capitalize-vs-expense
triggers:
  - should we capitalize or expense this
  - capex vs opex treatment
  - capitalization decision for a cost
tools_needed:
  - knowledge_search
---
# What this skill does

Determines the correct accounting treatment of a specific cost — capitalize as an asset or expense in the period — under the entity's governing framework (US GAAP, IFRS) and capitalization policy. Produces a short capitalization memo stating the conclusion, the policy and standard basis, the asset class, and the useful life / amortization or depreciation period.

# Steps

1. Pull the actual cost facts: vendor invoice or PO, amount, what was acquired (tangible asset, software, R&D, repair, internal labor), date placed in service, and whether it extends life or restores existing condition. Never assume the amount or nature — cite the source document.
2. Retrieve the governing rule with `knowledge_search`: the entity's capitalization policy (capitalization threshold, asset-class useful lives) and the applicable standard (e.g. ASC 360 PP&E, ASC 350-40 internal-use software, ASC 730 R&D, IAS 16, IAS 38). Quote the threshold and the recognition criteria; mark any rule you cannot locate as unverified.
3. Apply the test: does the cost create or extend a future economic benefit beyond one period AND exceed the capitalization threshold? If yes, assign asset class, useful life, and method; if no (routine repair/maintenance, below threshold, sustaining R&D), expense it. Note borderline items (betterment vs repair, software dev vs preliminary stage).
4. Report the conclusion in a capitalization memo: treatment, dollar amount, asset class, useful life, standard + policy citation, and any judgment calls flagged for controller review. State assumptions explicitly.

# Notes

Output is wrong if it ignores the entity's stated capitalization threshold, applies the wrong standard (R&D vs software vs PP&E have different rules), or treats a repair as a betterment. The threshold and useful-life tables are entity-specific — do not import generic numbers; mark them unverified if `knowledge_search` returns nothing. This skill drafts and recommends a treatment; the controller or auditor approves the final accounting entry. Do not use it to decide tax depreciation (book vs tax differ — that is a separate analysis) or to override an existing audited policy without escalation.
