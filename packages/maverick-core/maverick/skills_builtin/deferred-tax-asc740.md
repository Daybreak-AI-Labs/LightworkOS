---
name: deferred-tax-asc740
triggers:
  - asc 740
  - tax provision
  - deferred tax
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Computes a U.S. GAAP income-tax provision under ASC 740 from a trial balance and book-tax differences: current and deferred components, deferred tax assets/liabilities by temporary difference, the effective-rate reconciliation, and a valuation-allowance assessment. Produces a provision workpaper that ties total tax expense to pre-tax book income and explains every reconciling item.

# Steps

1. Pull pre-tax book income, the chart of accounts, and the prior-year provision/deferred rollforward from the source ledger via `spreadsheet`. Confirm the entity legal structure, jurisdictions, and applicable statutory rates with `knowledge_search`; mark any rate you cannot source as unverified.
2. Schedule book-tax differences into permanent (M-1 permanents: meals, fines, tax-exempt income) and temporary (depreciation, accruals, reserves, NOLs, stock comp). Compute current taxable income and current tax = taxable income x statutory rate by jurisdiction.
3. Build the deferred inventory: multiply each cumulative temporary difference and carryforward by the enacted rate expected to apply on reversal (not the current-year rate if a change is enacted). Net into DTAs and DTLs; roll forward against the prior-year balances so the deferred expense/benefit equals the period change.
4. Assess the valuation allowance against DTAs using the more-likely-than-not standard, weighing positive and negative evidence (cumulative losses, projected income, reversal patterns). Build the rate reconciliation from statutory to effective rate and confirm total expense ties to the deferred rollforward + current tax. Report the provision, DTA/DTL schedule, VA conclusion, and rate rec; flag every estimate and assumption for tax-preparer review.

# Notes

Output is wrong if cumulative (not annual) temporary differences are used, if the current-year rate is applied to deferreds when a rate change is enacted, or if permanents leak into the deferred schedule. Enacted-rate vs proposed-rate is a common error — only enacted law affects deferreds. Valuation-allowance judgment and uncertain tax positions (ASC 740-10/FIN 48) are advisory only: stage them as recommendations for a qualified tax professional, never as a filed position. Do not use for non-U.S. GAAP regimes (IAS 12 differs) or for interim provisions requiring an annual effective-rate estimate without flagging the method difference.
