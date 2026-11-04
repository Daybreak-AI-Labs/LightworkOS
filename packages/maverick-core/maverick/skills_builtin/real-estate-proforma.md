---
name: real-estate-proforma
triggers:
  - build a real estate proforma
  - underwrite this property
  - what's the cap rate and IRR
tools_needed:
  - spreadsheet
---
# What this skill does

Underwrites a property investment by building a financial proforma from the deal's rent roll, operating data, and financing terms. Produces a proforma with net operating income (NOI), cap rate, levered/unlevered IRR, and a sensitivity analysis so the return profile and its key risks are explicit.

# Steps

1. Collect the deal inputs: purchase price, rent roll (units, in-place and market rents, occupancy), operating expenses, capex/reserves, and financing terms (loan amount, rate, amortization, hold period). Note which figures are actuals vs. broker/seller pro-forma assumptions and treat the latter as unverified.
2. Build the cash-flow model in `spreadsheet`: gross potential rent, vacancy/credit loss, effective gross income, operating expenses, and NOI per year over the hold; show each line and its driver.
3. Compute the return metrics: going-in and exit cap rate, exit value (NOI / exit cap), debt service and levered cash flows, and both unlevered and levered IRR plus equity multiple. State every assumption (rent growth, exit cap, vacancy) explicitly.
4. Run a sensitivity table (e.g. IRR vs. exit cap and rent growth) and deliver the proforma. Report results, separate verified inputs from assumptions, and hand off for review — recommend, do not commit capital.

# Notes

The proforma is wrong if NOI omits a real expense line, if exit value uses an unjustified cap rate, or if seller pro-forma rents are taken as in-place actuals. Garbage-in dominates: an optimistic exit cap or rent-growth assumption can manufacture any IRR, so sensitivities are mandatory. Investment commitment is irreversible and stays with the human decision-maker. Do not use without a rent roll and financing terms, or for development/ground-up deals (needs a construction-budget model instead).
