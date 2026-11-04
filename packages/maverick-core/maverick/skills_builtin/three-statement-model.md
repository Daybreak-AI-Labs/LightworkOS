---
name: three-statement-model
triggers:
  - build a three statement model
  - financial model
  - 3 statement model
tools_needed:
  - spreadsheet
---
# What this skill does

Builds an integrated three-statement financial model (income statement, balance sheet, cash flow statement) where the three statements are mechanically linked so net income, retained earnings, cash, and the financing/working-capital lines reconcile. Produces a single spreadsheet with a driver block, the three statements, and built-in integrity checks (balance sheet ties, cash flow ties to the cash line).

# Steps

1. Gather the source inputs: historical financials (at least the last full period) and the assumption set (revenue growth, margins, capex, depreciation policy, tax rate, working-capital days, debt schedule). Read them from the provided files; do not invent figures — flag any missing assumption and stop on the gap.
2. In the spreadsheet, lay out a clearly separated drivers/assumptions block, then build the income statement down to net income, referencing only the driver cells (never hard-code growth into a statement row).
3. Build the balance sheet and cash flow statement, linking: net income -> retained earnings; cash flow -> the balance sheet cash line; capex/depreciation -> PP&E; working-capital days -> current asset/liability lines; debt schedule -> interest and balances.
4. Add integrity checks as explicit formula cells: balance sheet check (assets - liabilities - equity = 0), cash-flow-to-balance-sheet cash tie, and a circularity flag if interest feeds cash feeds interest. Report which checks pass, state every assumption used, and hand the workbook back for review before it informs any decision.

# Notes

The model is wrong if any check cell is non-zero, if a statement row hard-codes a value that should flow from a driver, or if circular interest is left unresolved (use an iterative-calc toggle or a circuit breaker, and say which). Garbage assumptions produce a clean-looking but meaningless model — always surface the assumption block to the reviewer. Do not use this for a quick one-statement projection or a valuation-only ask; this is the full linked engine. The model is a draft analytical tool; a human owns the assumptions and any decision built on the output.
