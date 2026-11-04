---
name: billings-to-revenue-recon
triggers:
  - billings to revenue
  - bookings recon
  - reconcile saas metrics
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reconciles the SaaS revenue chain — bookings (contract value signed) -> billings (invoiced) -> recognized revenue — for a period, surfacing the bridging items (deferred revenue movement, backlog/RPO, unbilled) that explain the gaps. Produces a bookings-billings-revenue reconciliation that ties each stage to the next with named adjustments.

# Steps

1. Pull period bookings, billings, recognized revenue, and opening/closing deferred revenue from the source system via sql_query; record the period, currency, and source tables. Do not substitute proxies — if a figure is missing, flag it rather than estimating.
2. Bridge bookings -> billings using billing-schedule timing (multi-year/annual-upfront vs in-arrears) and any unbilled/backlog movement; each adjustment must trace to data.
3. Bridge billings -> revenue via the deferred-revenue identity: Revenue = Billings - (Closing deferred - Opening deferred), plus any manual revenue adjustments. Confirm the deferred roll-forward (open + billings - revenue = close) holds.
4. Assemble both bridges in the spreadsheet, reconcile each stage to zero residual, and report the reconciliation with every bridging item named and sourced. State any unverified figure and surface residuals explicitly.

# Notes

The recon is wrong if a stage carries an unexplained residual, if deferred-revenue roll-forward does not close, or if FX/period boundaries are mixed. Bookings is contract value and is NOT additive into the deferred identity — keep the bookings->billings bridge separate from the billings->revenue bridge. This is a read-only analysis: it does not post journal entries or adjust the ledger — flag discrepancies for finance to resolve. Do not use for cash-basis books where deferred revenue is not tracked.
