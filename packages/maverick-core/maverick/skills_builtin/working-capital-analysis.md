---
name: working-capital-analysis
triggers:
  - working capital analysis
  - cash conversion cycle
  - dso dpo dio
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses how much cash is tied up in day-to-day operations by computing net working capital and the cash conversion cycle (DSO + DIO - DPO). Produces an analysis that quantifies the cash impact of each component and points to where cash can be released.

# Steps

1. Pull the inputs from the source of record (sql_query the GL/AR/AP/inventory tables or read the provided financials): revenue, COGS, accounts receivable, inventory, and accounts payable for each period in scope. Confirm the period basis (annual vs. annualized) before computing ratios.
2. Compute the components: DSO = AR / revenue x days, DIO = inventory / COGS x days, DPO = AP / COGS x days, then cash conversion cycle = DSO + DIO - DPO. Use period-average balances where available and note if you used period-end instead.
3. Build the trend: lay out CCC and each component across periods, compute net working capital (current operating assets - current operating liabilities), and translate day-changes into dollars (e.g. one DSO day = revenue/365). Identify the largest swings and their driver line.
4. Report the deliverable: a working-capital table with CCC trend, the dollar cash impact per component, and 2-3 grounded levers (collect AR faster, reduce inventory, extend payables). State the period basis and any balance you proxied; mark assumptions unverified.

# Notes

The output is wrong if the ratio denominators are mismatched (DSO must use revenue; DIO/DPO must use COGS, not revenue) or if period-end balances are treated as averages without saying so — both distort the cycle. Seasonality makes a single period-end snapshot misleading; prefer trailing averages and flag seasonal businesses. Negative CCC is legitimate (supplier-financed models) — do not "fix" it. This is diagnostic and advisory: recommendations are staged for a human; do not auto-change payment terms or credit policy, which are irreversible commercial actions.
