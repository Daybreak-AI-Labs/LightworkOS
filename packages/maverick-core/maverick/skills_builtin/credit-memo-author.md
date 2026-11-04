---
name: credit-memo-author
triggers:
  - write a credit memo
  - loan write up
  - credit analysis for this borrower
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Authors a credit memo supporting a lending decision on a specific borrower and facility. Produces a structured memo covering cash-flow capacity, collateral, and a risk rating with a clear recommendation, grounded in the borrower's financials and the lender's credit policy.

# Steps

1. Retrieve the deal facts and policy: borrower financials (statements, tax returns), requested facility (amount, tenor, structure), and the applicable credit policy and rating scale via `knowledge_search`. Note the statement period and any figures that are stale or unaudited.
2. Build the cash-flow analysis in `spreadsheet`: historical and projected cash flow, debt service coverage (DSCR), leverage, and liquidity ratios. Show formulas and inputs; do not assert a coverage ratio you have not computed from the source numbers.
3. Assess collateral (type, value, basis of valuation, LTV, lien position) and qualitative factors (industry, management, guarantor support). Flag any valuation that is an estimate vs. a third-party appraisal.
4. Assign a risk rating per the policy scale, state the recommendation (approve / approve-with-conditions / decline) and conditions/covenants, and write the memo. Report all assumptions and unverified figures; the memo is a recommendation — the credit committee or authorized officer makes the decision.

# Notes

The memo is wrong if ratios aren't derived from the actual financials, if collateral value is overstated or its valuation basis is unstated, or if the rating doesn't follow the documented scale. Never approve or fund — credit decisions are irreversible and reserved for the authorized approver/committee. Cite every source figure; mark projections and unaudited statements as such. Do not use without borrower financials or a defined facility.
