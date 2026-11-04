---
name: covenant-compliance-check
triggers:
  - run the covenant compliance check
  - are we in compliance with the debt covenants
  - prepare the compliance certificate
tools_needed:
  - spreadsheet
  - sql_query
---
# What this skill does

Tests a borrower's compliance with financial and negative covenants in a credit agreement as of a measurement date, computing each covenant ratio exactly as defined in the agreement (including its specific add-back and exclusion definitions). Produces a covenant compliance check showing each covenant's required level, actual level, headroom/cushion, and pass/fail, formatted to support the compliance certificate.

# Steps

1. Extract the covenant definitions from the credit agreement: each financial covenant (e.g. max total/senior leverage, min fixed-charge or interest coverage, min liquidity), its required threshold for the test date, the measurement frequency, and the EXACT defined-term formula for Consolidated EBITDA, Total Debt, Fixed Charges, etc. Cite section numbers; the agreement's definitions override standard definitions.
2. Pull the underlying financials from `sql_query` or the close package for the test period (typically TTM EBITDA, period-end debt balances, cash interest, scheduled amortization, taxes, capex per the FCCR definition). Anchor to reported balances and cite the source.
3. Compute each ratio in `spreadsheet` strictly per the agreement's defined terms — apply only the add-backs the agreement permits (cap any capped add-backs), then compare to the required level. Calculate headroom (absolute cushion to the threshold) and the percentage cushion; show the EBITDA decline that would trip each covenant.
4. Report the compliance check: per-covenant required vs actual, pass/fail, headroom and cushion, and any covenant within a defined warning band. Flag definitional judgment calls and tie the output to the compliance certificate line items for treasurer/CFO sign-off.

# Notes

Output is wrong if it uses a generic EBITDA or leverage definition instead of the agreement's defined terms, applies uncapped add-backs the agreement caps, or uses the wrong measurement-date balances (period-end vs average debt matters). A miss is high-stakes: a tripped covenant can trigger default and acceleration. This skill computes and drafts the certificate; the treasurer/CFO certifies and signs — never self-certify or notify the lender. Do not use it to interpret cure rights, equity-cure mechanics, or waiver terms (route to counsel); flag a projected breach for human escalation rather than acting on it.
