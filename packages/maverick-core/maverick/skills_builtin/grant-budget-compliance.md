---
name: grant-budget-compliance
triggers:
  - grant compliance
  - allowable cost
  - grant budget
---
# What this skill does

Reviews grant expenditures against the approved grant budget and the funder's cost rules, checking that spend is allowable, within line-item budget, and properly allocated. Produces a compliance review listing budget overruns, unallowable costs, and items needing documentation, each tied to the governing rule.

# Steps

1. Retrieve the governing rules via `knowledge_search` — the award budget by cost category, the funder's allowable/unallowable cost criteria (e.g. Uniform Guidance 2 CFR 200 for federal awards), indirect/F&A rate, and the period of performance; capture citations.
2. Load actual spend per cost category and the budget into `spreadsheet`; compute spent, budget, remaining, and percent-utilized per line, plus burn rate against the period of performance.
3. Test each category: budget-line overruns (and whether rebudgeting authority/cap applies), expenses outside the performance period, costs hitting the funder's unallowable list (e.g. alcohol, entertainment, certain travel), missing cost-share, and indirect computed off the wrong base. Cite the rule per finding.
4. Assemble the review — overruns, unallowable costs, documentation gaps, and remaining-budget runway — and hand off, stating the award/budget version and rule source used and flagging any category where allowability is ambiguous for the grants officer rather than ruling unilaterally.

# Notes

Output is wrong if it tests against the wrong award version (budgets get amended — confirm the current approved budget), applies the wrong allowability framework (federal vs foundation rules differ), or computes indirect on the wrong base (MTDC excludes certain lines). Allowability calls in gray areas are for the grants/compliance officer — recommend, don't adjudicate. This is a review draft; it does not move costs, file rebudget requests, or disallow charges. Don't use it without the actual award terms and approved budget in hand — generic rules alone aren't sufficient.
