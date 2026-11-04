---
name: treasury-cash-positioning
triggers:
  - cash positioning
  - run the daily treasury position
  - cash sweep
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds the daily cash position across all bank accounts and currencies, projects intraday and next-day flows, and produces a positioning worksheet with concrete sweep recommendations (concentrate to a master account, fund overdrafts, invest excess to money-market). Output is a worksheet a treasury analyst signs off before any transfer is initiated.

# Steps

1. Pull opening ledger balances per account from the treasury/bank-feed source with `sql_query` (account, currency, available balance, value date, as-of timestamp). Record the as-of time; a stale feed makes every number wrong.
2. Layer known same-day flows onto each balance: AP runs, payroll, debt service, tax payments, expected receipts. Source each from the AP/AR or forecast tables; mark any manually-entered or unconfirmed flow as `unverified`.
3. Compute projected end-of-day available balance per account and per currency in `spreadsheet`. Flag accounts below their minimum/target buffer and accounts holding idle excess above target.
4. Generate sweep recommendations: amount, from-account, to-account, and rationale, respecting account minimums, currency boundaries (no implicit FX), and counterparty/instrument limits. Report the worksheet and stage transfers as recommendations only — do not initiate. State assumptions (FX rates used, cutoff times, which flows were unverified) and hand off to the analyst for approval.

# Notes

Wrong if the balance feed is stale, value dates are ignored (a future-dated credit is not available cash), or currencies are netted without an FX assumption. Never auto-execute sweeps — moving cash is irreversible; this skill drafts and recommends, a human authorizes. Respect minimum operating balances and any restricted/pledged accounts. Do not use for multi-day liquidity forecasting or investment strategy — this is intraday/next-day positioning only.
