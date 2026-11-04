---
name: qoe-analysis
triggers:
  - build a quality of earnings analysis
  - run the QoE
  - normalize EBITDA for the deal
tools_needed:
  - spreadsheet
  - sql_query
---
# What this skill does

Builds or reviews a quality-of-earnings (QoE) analysis that bridges reported net income to a normalized, run-rate adjusted EBITDA for diligence on a target. Produces a QoE schedule with itemized EBITDA adjustments (non-recurring, owner, accounting, pro-forma) and quality flags on revenue recognition, working capital, and adjustment durability.

# Steps

1. Pull the source financials: trial balance and P&L by period from `sql_query` (or the provided GL extract), plus the management adjustment list. Anchor to the actual reported figures and the period covered (typically TTM and 3 prior years); cite the data source and close date.
2. Start from reported EBITDA and layer adjustments in `spreadsheet`, one row each with amount, period, and rationale: non-recurring items (legal settlements, one-time gains), owner/related-party normalizations (above/below-market comp, personal expenses), accounting corrections (cutoff, revenue recognition, capitalized vs expensed), and run-rate/pro-forma items (acquisitions, closures, price changes). Sign and support each from a document.
3. Apply quality flags: assess revenue recognition policy and concentration, working-capital trend and the debt-free-net-working-capital peg, customer churn, and the durability of each add-back (recurring add-backs are low quality). Separate evidence-supported adjustments from management-asserted ones.
4. Report the QoE: bridge from reported to adjusted EBITDA, the adjustment schedule with support level per line, working-capital peg, and a quality-flag summary. State which adjustments are unverified or management-only, and hand off for diligence-team review.

# Notes

Output is wrong if add-backs are accepted without support, if recurring costs are dressed as one-time, if revenue cutoff and channel-stuffing risks are not tested, or if the working-capital peg is omitted (it directly moves the purchase price). Adjusted EBITDA is a non-GAAP construct — never present it as audited; mark management-asserted add-backs as unverified pending diligence. This skill produces a diligence draft that informs valuation and the SPA peg; the deal team and QoE provider sign off. Do not use it as a substitute for an audit or for final purchase-price true-up.
