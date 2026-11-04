---
name: fx-exposure-analysis
triggers:
  - what's our FX exposure by currency
  - run a currency risk analysis
  - should we hedge our EUR position
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Quantifies currency exposure across the balance sheet and forecast cash flows, then frames hedging options. It aggregates monetary assets/liabilities and expected flows by currency, computes net exposure and a sensitivity to rate moves, and recommends a hedge ratio and instrument profile. Output is an FX-exposure analysis a treasurer can take to a hedging decision.

# Steps

1. Assemble exposures with `pandas_query`: per-currency monetary assets and liabilities (cash, AR, AP, intercompany, debt) plus forecast inflows/outflows over the hedge horizon. Record the as-of date and the functional/reporting currency; mark forecast flows as estimates with their confidence/source.
2. Compute net exposure per currency (assets + expected inflows − liabilities − expected outflows), converted to reporting currency at the stated spot rate. Cite the rate source and timestamp; never invent rates.
3. In `spreadsheet`, run sensitivity: revalue each net exposure under defined rate shocks (e.g. +/-5%, +/-10%) and report the P&L/cash impact per scenario. Identify the currencies driving the majority of risk.
4. Recommend a hedge ratio per material currency tied to the entity's risk policy/tolerance (if a policy is on file, cite it; if not, mark the assumption). Map each to an instrument profile (forward, option, natural offset) with rough notional and tenor; note that quotes are indicative until a desk prices them.
5. Report net exposure by currency, the sensitivity table, the top risk drivers, and staged hedge recommendations. State assumptions (rate source/date, forecast confidence, policy basis) and hand off; do not execute trades or commit notionals — that is the treasurer's call.

# Notes

The analysis is wrong if accounting exposure (balance-sheet monetary items) is mixed with economic/forecast exposure without labeling which is hedged, or if a single stale spot rate is applied across as-of dates — timestamp every rate. Forecast flows carry estimation risk; over-hedging an uncertain forecast creates a new exposure. This skill sizes and recommends only; entering forwards/options or committing notional is irreversible and requires treasurer approval within policy. Do not use it for transaction-level FX gain/loss accounting or for a one-off rate conversion.
